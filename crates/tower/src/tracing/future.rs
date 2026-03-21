use std::task::ready;

use pin_project_lite::pin_project;
use tracing::Span;

pin_project! {
    pub struct TraceFuture<F, OnResponse, OnError> {
        #[pin]
        inner: F,
        span: Span,
        on_response: OnResponse,
        on_error: OnError,
    }
}

impl<F, OnResponse, OnError> TraceFuture<F, OnResponse, OnError> {
    pub fn new(inner: F, span: Span, on_response: OnResponse, on_error: OnError) -> Self {
        Self {
            inner,
            span,
            on_response,
            on_error,
        }
    }
}

impl<F, R, E, OnResponse, OnError> Future for TraceFuture<F, OnResponse, OnError>
where
    F: Future<Output = Result<R, E>>,
    OnResponse: super::enrich_span::EnrichSpan<R>,
    OnError: super::enrich_span::EnrichSpan<E>,
{
    type Output = Result<R, E>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.project();

        // Poll the inner future, with the span entered. This is effectively what
        // [`tracing::Instrumented`] does.
        let _guard = this.span.enter();
        let result = ready!(this.inner.poll(cx));

        match &result {
            Ok(response) => {
                this.on_response.enrich_span(this.span, response);
            }
            Err(error) => {
                this.on_error.enrich_span(this.span, error);
            }
        }

        std::task::Poll::Ready(result)
    }
}
