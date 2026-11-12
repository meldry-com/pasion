//! Semantic validation for Matrix *login* grants, separate from generic
//! OAuth scope syntax and from administrative personal-token delegation.
use std::collections::BTreeSet;

use crate::scope::Scope;

/// The requested Matrix login has an absent, empty or ambiguous device binding.
#[derive(Debug, thiserror::Error)]
#[error("a Matrix login must bind exactly one non-empty device ID")]
pub struct InvalidMatrixLoginScope;

/// Validate the device binding of a Matrix authorization/device-code login.
/// Ordinary OIDC scopes do not require a Matrix device. Stable and MSC scope
/// aliases for the same ID describe one device; aliases for different IDs do
/// not. This must not be applied to generic PAT creation or service delegation.
///
/// # Errors
///
/// Returns an error if a Matrix login has zero devices, an empty device ID,
/// or more than one distinct device ID after resolving scope aliases.
pub fn validate_matrix_login_scope(scope: &Scope) -> Result<(), InvalidMatrixLoginScope> {
    let mut matrix = false;
    let mut devices = BTreeSet::new();
    for token in scope.iter() {
        let token = token.as_str();
        if token.starts_with("urn:matrix:client:api:")
            || token.starts_with("urn:matrix:org.matrix.msc2967.client:api:")
        {
            matrix = true;
        }
        if let Some(id) = token
            .strip_prefix("urn:matrix:client:device:")
            .or_else(|| token.strip_prefix("urn:matrix:org.matrix.msc2967.client:device:"))
        {
            matrix = true;
            if id.is_empty() {
                return Err(InvalidMatrixLoginScope);
            }
            devices.insert(id);
        }
    }
    if matrix && devices.len() != 1 {
        return Err(InvalidMatrixLoginScope);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_login_requires_one_device_but_oidc_does_not() {
        for scope in [
            "openid email",
            "urn:pasion:admin",
            "openid urn:matrix:client:api:* urn:matrix:client:device:A",
            "urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:A",
            "urn:matrix:client:device:A urn:matrix:org.matrix.msc2967.client:device:A",
        ] {
            assert!(
                validate_matrix_login_scope(&scope.parse().unwrap()).is_ok(),
                "{scope}"
            );
        }
        for scope in [
            "urn:matrix:client:api:*",
            "urn:matrix:org.matrix.msc2967.client:api:*",
            "urn:matrix:client:device:",
            "urn:matrix:client:device:A urn:matrix:client:device:B",
            "urn:matrix:client:device:A urn:matrix:org.matrix.msc2967.client:device:B",
            "urn:matrix:client:device:A urn:matrix:org.matrix.msc2967.client:device:",
        ] {
            assert!(
                validate_matrix_login_scope(&scope.parse().unwrap()).is_err(),
                "{scope}"
            );
        }
    }
}
