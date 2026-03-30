//! Authenticator validation stage side effects.
//!
//! Validates a second-factor code (TOTP for now).  The current MVP checks
//! code format only; actual TOTP secret lookup and HMAC verification is
//! deferred until TOTP secret storage is implemented.

use pasion_data::flow::{StageOutcome, StageValidationError};

use super::StageExecutionError;

/// Execute the authenticator validation stage.
///
/// For the TOTP MVP this validates the code format (exactly 6 ASCII digits)
/// and marks `mfa_validated` in the flow context.  Full TOTP secret lookup
/// and HMAC verification will be added once TOTP secret storage is in place.
pub async fn execute(
    code: &str,
    context: &mut serde_json::Value,
) -> Result<StageOutcome, StageExecutionError> {
    // Validate that a user has been identified in a previous stage.
    let _user_id = context
        .get("user_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            StageExecutionError::Internal(anyhow::anyhow!(
                "missing user_id in flow context — identification stage must run first"
            ))
        })?;

    // MVP: validate code format (6 ASCII digits).
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return Ok(StageOutcome::Retry {
            errors: vec![StageValidationError {
                field: Some("code".into()),
                message: "Code must be exactly 6 digits".into(),
                code: "invalid_totp_code".into(),
            }],
        });
    }

    // TODO: look up the user's TOTP secret and verify the HMAC when
    // TOTP secret storage is implemented.

    // Mark MFA as validated in the flow context.
    if let Some(ctx) = context.as_object_mut() {
        ctx.insert("mfa_validated".into(), serde_json::json!(true));
    }

    Ok(StageOutcome::Continue)
}
