use opentelemetry_semantic_conventions::attribute::DB_QUERY_TEXT;
use tracing::Span;

/// Records a SQL statement string into the current tracing span as
/// `db.query.text`. Used by new diesel-based repository code.
#[allow(dead_code)]
pub(crate) fn trace_query(sql: &str) {
    Span::current().record(DB_QUERY_TEXT, sql);
}

/// An extension trait for [`sqlx::Execute`] that records the SQL statement as
/// `db.query.text` in a tracing span.
///
/// Kept for backward compatibility during the sqlx → diesel migration.
pub trait ExecuteExt<'q, DB>: Sized {
    /// Records the statement as `db.query.text` in the current span
    #[must_use]
    fn traced(self) -> Self {
        self.record(&Span::current())
    }

    /// Records the statement as `db.query.text` in the given span
    #[must_use]
    fn record(self, span: &Span) -> Self;
}

impl<'q, DB, T> ExecuteExt<'q, DB> for T
where
    T: sqlx::Execute<'q, DB>,
    DB: sqlx::Database,
{
    fn record(self, span: &Span) -> Self {
        span.record(DB_QUERY_TEXT, self.sql());
        self
    }
}
