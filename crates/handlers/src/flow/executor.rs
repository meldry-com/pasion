use pasion_data_model::flow::*;
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FlowPlannerError {
    #[error("flow not found: {0}")]
    FlowNotFound(String),

    #[error("flow session expired")]
    SessionExpired,

    #[error("flow session already completed")]
    AlreadyCompleted,

    #[error("no more stages in flow")]
    NoMoreStages,

    #[error(transparent)]
    Repository(#[from] pasion_storage::RepositoryError),
}

/// A planned flow — the ordered list of stage bindings to execute.
pub struct FlowPlan {
    pub flow: FlowDefinition,
    pub stages: Vec<FlowStageBinding>,
}

/// The flow executor manages progression through a flow's stages.
pub struct FlowExecutor;

impl FlowExecutor {
    /// Plan a flow: determine which stages should run based on context.
    /// For now, all stages in the flow are included (no policy evaluation).
    pub fn plan(flow: FlowDefinition, bindings: Vec<FlowStageBinding>) -> FlowPlan {
        let mut stages = bindings;
        stages.sort_by_key(|b| b.order);
        FlowPlan { flow, stages }
    }

    /// Get the challenge for the current stage of a flow session.
    pub fn current_challenge(
        plan: &FlowPlan,
        session: &FlowSession,
    ) -> Result<StageChallenge, FlowPlannerError> {
        if session.status.is_terminal() {
            return Err(FlowPlannerError::AlreadyCompleted);
        }

        let binding = plan
            .stages
            .get(session.current_stage_index)
            .ok_or(FlowPlannerError::NoMoreStages)?;

        Ok(challenge_for_stage(&binding.stage, &session.context))
    }

    /// Process a response for the current stage and determine the outcome.
    /// Returns the outcome and the updated context.
    pub fn process_response(
        plan: &FlowPlan,
        session: &FlowSession,
        response: StageResponse,
    ) -> Result<(StageOutcome, Value), FlowPlannerError> {
        if session.status.is_terminal() {
            return Err(FlowPlannerError::AlreadyCompleted);
        }

        let binding = plan
            .stages
            .get(session.current_stage_index)
            .ok_or(FlowPlannerError::NoMoreStages)?;

        let mut context = session.context.clone();
        let outcome = validate_response(&binding.stage, &response, &mut context);

        Ok((outcome, context))
    }

    /// Check if the flow has more stages after the current one.
    pub fn has_next_stage(plan: &FlowPlan, session: &FlowSession) -> bool {
        session.current_stage_index + 1 < plan.stages.len()
    }
}

/// Generate a challenge from a stage kind and current context.
fn challenge_for_stage(stage: &StageKind, context: &Value) -> StageChallenge {
    match stage {
        StageKind::Identification {
            user_fields,
            password_stage,
        } => StageChallenge::Identification {
            user_fields: user_fields.clone(),
            password_stage: *password_stage,
        },
        StageKind::EmailVerification { purpose, .. } => {
            let email = context
                .get("email")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            StageChallenge::EmailVerification {
                email,
                purpose: purpose.clone(),
            }
        }
        StageKind::PasswordWrite { require_current } => StageChallenge::PasswordWrite {
            require_current: *require_current,
        },
        StageKind::UserWrite { .. } => {
            let suggested = context
                .get("username")
                .and_then(|v| v.as_str())
                .map(|s| s.to_owned());
            StageChallenge::UserWrite {
                suggested_username: suggested,
            }
        }
        StageKind::Captcha => StageChallenge::Captcha {
            site_key: context
                .get("captcha_site_key")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned(),
        },
        StageKind::Consent => StageChallenge::Consent {
            scope: context
                .get("scope")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned(),
            client_name: context
                .get("client_name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_owned()),
        },
        StageKind::Prompt { fields } => StageChallenge::Prompt {
            fields: fields.clone(),
        },
        StageKind::AuthenticatorValidate { allowed_types } => {
            StageChallenge::AuthenticatorValidate {
                allowed_types: allowed_types.clone(),
            }
        }
    }
}

/// Validate a stage response and produce an outcome.
fn validate_response(
    stage: &StageKind,
    response: &StageResponse,
    context: &mut Value,
) -> StageOutcome {
    match (stage, response) {
        (
            StageKind::Identification { .. },
            StageResponse::Identification {
                uid_field,
                password,
            },
        ) => {
            // Store identified user in context
            if let Some(ctx) = context.as_object_mut() {
                ctx.insert("uid_field".into(), Value::String(uid_field.clone()));
                if let Some(pw) = password {
                    ctx.insert("password_provided".into(), Value::Bool(true));
                    // Don't store password in context for security
                    let _ = pw;
                }
            }
            StageOutcome::Continue
        }
        (
            StageKind::EmailVerification { .. },
            StageResponse::EmailVerification { code },
        ) => {
            // Actual verification happens in the stage implementation (side effect).
            // The executor just validates the response shape.
            if code.is_empty() {
                StageOutcome::Retry {
                    errors: vec![StageValidationError {
                        field: Some("code".into()),
                        message: "Verification code is required".into(),
                        code: "required".into(),
                    }],
                }
            } else {
                StageOutcome::Continue
            }
        }
        (
            StageKind::PasswordWrite { require_current },
            StageResponse::PasswordWrite {
                current_password,
                new_password,
            },
        ) => {
            let mut errors = vec![];
            if *require_current && current_password.is_none() {
                errors.push(StageValidationError {
                    field: Some("current_password".into()),
                    message: "Current password is required".into(),
                    code: "required".into(),
                });
            }
            if new_password.is_empty() {
                errors.push(StageValidationError {
                    field: Some("new_password".into()),
                    message: "New password is required".into(),
                    code: "required".into(),
                });
            }
            if errors.is_empty() {
                StageOutcome::Continue
            } else {
                StageOutcome::Retry { errors }
            }
        }
        (
            StageKind::UserWrite { .. },
            StageResponse::UserWrite {
                username,
                display_name,
            },
        ) => {
            if let Some(ctx) = context.as_object_mut() {
                ctx.insert("username".into(), Value::String(username.clone()));
                if let Some(dn) = display_name {
                    ctx.insert("display_name".into(), Value::String(dn.clone()));
                }
            }
            StageOutcome::Continue
        }
        (StageKind::Consent, StageResponse::Consent { granted }) => {
            if *granted {
                StageOutcome::Continue
            } else {
                StageOutcome::Done {
                    redirect_to: None,
                }
            }
        }
        (StageKind::Captcha, StageResponse::Captcha { token }) => {
            if token.is_empty() {
                StageOutcome::Retry {
                    errors: vec![StageValidationError {
                        field: Some("token".into()),
                        message: "CAPTCHA token is required".into(),
                        code: "required".into(),
                    }],
                }
            } else {
                StageOutcome::Continue
            }
        }
        (
            StageKind::Prompt { fields },
            StageResponse::Prompt { data },
        ) => {
            let mut errors = vec![];
            for field in fields {
                if field.required {
                    let value = data.get(&field.field_key);
                    let is_missing = match value {
                        None | Some(Value::Null) => true,
                        Some(Value::String(s)) if s.is_empty() => true,
                        _ => false,
                    };
                    if is_missing {
                        errors.push(StageValidationError {
                            field: Some(field.field_key.clone()),
                            message: format!("{} is required", field.label),
                            code: "required".into(),
                        });
                    }
                }
            }
            if errors.is_empty() {
                if let Some(ctx) = context.as_object_mut() {
                    ctx.insert("prompt_data".into(), data.clone());
                }
                StageOutcome::Continue
            } else {
                StageOutcome::Retry { errors }
            }
        }
        (
            StageKind::AuthenticatorValidate { .. },
            StageResponse::AuthenticatorValidate { code, .. },
        ) => {
            if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
                StageOutcome::Retry {
                    errors: vec![StageValidationError {
                        field: Some("code".into()),
                        message: "Code must be exactly 6 digits".into(),
                        code: "invalid_totp_code".into(),
                    }],
                }
            } else {
                if let Some(ctx) = context.as_object_mut() {
                    ctx.insert("mfa_validated".into(), Value::Bool(true));
                }
                StageOutcome::Continue
            }
        }
        _ => {
            // Mismatched stage/response types
            StageOutcome::Retry {
                errors: vec![StageValidationError {
                    field: None,
                    message: "Invalid response for this stage".into(),
                    code: "invalid_response".into(),
                }],
            }
        }
    }
}
