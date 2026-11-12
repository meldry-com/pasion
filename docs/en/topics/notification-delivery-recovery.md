# Recovering ambiguous notification deliveries

The worker commits `sending` and its audit event before contacting a provider,
releases the database transaction while sending, and finalizes the result in a
new transaction. The send deadline is 60 seconds. Requests rejected explicitly
with HTTP 429 retain the existing bounded retry policy. An ambiguous transport
or server failure enters `failed` with failure code `delivery_outcome_unknown`,
`retryable=false` and no next retry time. This is an explicit unresolved outcome,
not proof of rejection.

After a worker crash, the minute delivery sweep expires sending leases older
than five minutes into that same unresolved failure classification. It never puts
these deliveries back in the send queue: the provider might already have accepted
the message. The sweep
handles at most 100 expired records per pass and skips locked rows. Delivery
finalization reloads and locks the attempt, so a callback or expiry result takes
precedence over a stale worker result. Existing stable delivery/request tracking
tags and provider-supported idempotency keys are preserved.

Operators should inspect the persisted failure details and correlate the
delivery ID, request ID and provider message ID with provider logs. An
authenticated delivered/failed webhook can reconcile an unknown result. For
channels without callbacks, verify acceptance at the provider before creating a
new notification request. Do not resend solely because the worker timed out or
the lease expired. This policy favors avoiding duplicate recovery/verification
messages; it cannot promise exactly-once delivery for providers without an
idempotency or status-query interface.

No schema migration or new status literal is required. Older readers can decode
the existing `failed` status and will not automatically retry it because
`next_retry_at` is NULL. During rolling deployment, route sends to upgraded
workers: an old worker still sends inside a transaction and cannot gain the new
crash guarantees. Old callback handlers also cannot reconcile an ambiguous failed
record to delivered, so retain upgraded handlers for unresolved deliveries or
reconcile them manually before rolling those handlers back.
