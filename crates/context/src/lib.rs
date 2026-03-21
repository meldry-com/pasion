//! Task-local logging context with CPU-time and poll-count tracking.
//!
//! [`LogContext`] is attached to each async task (via a Tokio `task_local!`)
//! and records how long the task has been alive, how many times it has been
//! polled, and an approximate CPU time. This information is emitted in
//! structured log lines for every HTTP response.
//!
//! # Usage
//!
//! ```ignore
//! let ctx = LogContext::new("http-request");
//! ctx.run(|| async { /* handler code */ }).await;
//! ```
//!
//! The context is automatically available inside the future via
//! [`LogContext::maybe_with`].

mod fmt;
mod future;

use std::{
    borrow::Cow,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use quanta::Instant;
use tokio::task_local;

pub use self::{
    fmt::EventFormatter,
    future::{LogContextFuture, PollRecordingFuture},
};

/// A counter which increments each time we create a new log context
/// It will wrap around if we create more than [`u64::MAX`] contexts
static LOG_CONTEXT_INDEX: AtomicU64 = AtomicU64::new(0);
task_local! {
    pub static CURRENT_LOG_CONTEXT: LogContext;
}

/// A log context saves informations about the current task, such as the
/// elapsed time, the number of polls, and the poll time.
#[derive(Clone)]
pub struct LogContext {
    inner: Arc<LogContextInner>,
}

struct LogContextInner {
    /// A user-defined tag for the log context
    tag: Cow<'static, str>,

    /// A unique index for the log context
    index: u64,

    /// The time when the context was created
    start: Instant,

    /// The number of [`Future::poll`] recorded
    polls: AtomicU64,

    /// An approximation of the total CPU time spent in the context, in
    /// nanoseconds
    cpu_time: AtomicU64,
}

impl LogContext {
    /// Create a new log context with the given tag
    pub fn new(tag: impl Into<Cow<'static, str>>) -> Self {
        let tag = tag.into();
        let inner = LogContextInner {
            tag,
            index: LOG_CONTEXT_INDEX.fetch_add(1, Ordering::Relaxed),
            start: Instant::now(),
            polls: AtomicU64::new(0),
            cpu_time: AtomicU64::new(0),
        };

        Self {
            inner: Arc::new(inner),
        }
    }

    /// Run a closure with the current log context, if any
    pub fn maybe_with<F, R>(f: F) -> Option<R>
    where
        F: FnOnce(&Self) -> R,
    {
        CURRENT_LOG_CONTEXT.try_with(f).ok()
    }

    /// Run the async function `f` with the given log context. It will wrap the
    /// output future to record poll and CPU statistics.
    pub fn run<F: FnOnce() -> Fut, Fut: Future>(&self, f: F) -> LogContextFuture<Fut> {
        let future = self.run_sync(f);
        self.wrap_future(future)
    }

    /// Run the sync function `f` with the given log context, recording the CPU
    /// time spent.
    pub fn run_sync<F: FnOnce() -> R, R>(&self, f: F) -> R {
        let start = Instant::now();
        let result = CURRENT_LOG_CONTEXT.sync_scope(self.clone(), f);
        let elapsed = start.elapsed().as_nanos().try_into().unwrap_or(u64::MAX);
        self.inner.cpu_time.fetch_add(elapsed, Ordering::Relaxed);
        result
    }

    /// Create a snapshot of the log context statistics
    #[must_use]
    pub fn stats(&self) -> LogContextStats {
        let polls = self.inner.polls.load(Ordering::Relaxed);
        let cpu_time = self.inner.cpu_time.load(Ordering::Relaxed);
        let cpu_time = Duration::from_nanos(cpu_time);
        let elapsed = self.inner.start.elapsed();
        LogContextStats {
            polls,
            cpu_time,
            elapsed,
        }
    }
}

impl std::fmt::Display for LogContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tag = &self.inner.tag;
        let index = self.inner.index;
        write!(f, "{tag}-{index}")
    }
}

/// A snapshot of a log context statistics
#[derive(Debug, Clone, Copy)]
pub struct LogContextStats {
    /// How many times the context was polled
    pub polls: u64,

    /// The approximate CPU time spent in the context
    pub cpu_time: Duration,

    /// How much time elapsed since the context was created
    pub elapsed: Duration,
}

impl std::fmt::Display for LogContextStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let polls = self.polls;
        #[expect(clippy::cast_precision_loss)]
        let cpu_time_ms = self.cpu_time.as_nanos() as f64 / 1_000_000.;
        #[expect(clippy::cast_precision_loss)]
        let elapsed_ms = self.elapsed.as_nanos() as f64 / 1_000_000.;
        write!(
            f,
            "polls: {polls}, cpu: {cpu_time_ms:.1}ms, elapsed: {elapsed_ms:.1}ms",
        )
    }
}
