//! REST API endpoints for the flow engine.
//!
//! These endpoints expose the flow engine over HTTP, allowing clients to start
//! flows, query the current challenge, and submit stage responses.
//!
//! Session state is stored in-memory for now; a proper repository-backed store
//! will replace this once `FlowSession` has a database repository.

use std::collections::HashMap;
use std::sync::LazyLock;

use chrono::Utc;
use pasion_data_model::flow::{
    FlowSession, FlowSessionStatus, StageChallenge, StageOutcome, StageResponse,
    StageValidationError,
};
use pasion_data_model::new_id;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::RwLock;
use ulid::Ulid;

use super::{RouteError, make_rng};
use crate::flow::{FlowExecutor, FlowPlan};

// ---------------------------------------------------------------------------
// In-memory session store
// ---------------------------------------------------------------------------

/// In-memory store for active flow sessions.
///
/// Maps `session_id -> (FlowPlan, FlowSession)`.  This is intentionally
/// simple — a proper database-backed store will replace this once
/// `FlowSession` gets a repository implementation.
static SESSION_STORE: LazyLock<RwLock<HashMap<Ulid, (FlowPlan, FlowSession)>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Envelope returned for every flow endpoint.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct FlowResponse {
    /// The session identifier (ULID).
    pub session_id: String,
    /// The slug of the flow being executed.
    pub flow_slug: String,
    /// The current stage challenge to present to the user.
    pub challenge: StageChallenge,
    /// Zero-based index of the current stage.
    pub stage_index: usize,
    /// Total number of stages in the flow.
    pub total_stages: usize,
    /// Validation errors, if the last response was rejected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<StageValidationError>>,
}

/// Request body for `POST /api/v1/flow/session/:id/respond`.
#[derive(Deserialize, ToSchema)]
pub struct RespondInput {
    /// The stage response submitted by the client.
    pub response: StageResponse,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve a flow definition + bindings from a slug using the built-in
/// defaults.  Returns `None` if the slug does not match any known default
/// flow.
fn resolve_flow_by_slug(
    slug: &str,
    rng: &mut impl rand::RngCore,
) -> Option<(
    pasion_data_model::flow::FlowDefinition,
    Vec<pasion_data_model::flow::FlowStageBinding>,
)> {
    match slug {
        "default-registration" => {
            Some(crate::flow::defaults::default_registration_flow(rng))
        }
        "default-recovery" => {
            Some(crate::flow::defaults::default_recovery_flow(rng))
        }
        "default-password-change" => {
            Some(crate::flow::defaults::default_password_change_flow(rng))
        }
        "default-authentication" => {
            Some(crate::flow::defaults::default_authentication_flow(rng))
        }
        _ => None,
    }
}

/// Build a [`FlowResponse`] from a plan, session, and challenge.
fn build_response(
    plan: &FlowPlan,
    session: &FlowSession,
    challenge: StageChallenge,
    errors: Option<Vec<StageValidationError>>,
) -> FlowResponse {
    FlowResponse {
        session_id: session.id.to_string(),
        flow_slug: plan.flow.slug.clone(),
        challenge,
        stage_index: session.current_stage_index,
        total_stages: plan.stages.len(),
        errors,
    }
}

// ---------------------------------------------------------------------------
// POST /api/v1/flow/:slug/start
// ---------------------------------------------------------------------------

/// Start a new flow session for the given flow slug.
///
/// Creates a `FlowSession`, plans the flow, and returns the first stage
/// challenge.
#[endpoint]
pub async fn start_flow(req: &mut Request) -> Result<Json<FlowResponse>, RouteError> {
    let slug: String = req
        .param::<String>("slug")
        .ok_or_else(|| RouteError::BadRequest("missing flow slug".into()))?;

    let mut rng = make_rng();

    let (flow_def, bindings) = resolve_flow_by_slug(&slug, &mut *rng)
        .ok_or_else(|| RouteError::NotFound)?;

    let plan = FlowExecutor::plan(flow_def, bindings);

    let now = Utc::now();
    let session_id = new_id(now, &mut *rng);

    let session = FlowSession {
        id: session_id,
        flow_id: plan.flow.id,
        current_stage_index: 0,
        status: FlowSessionStatus::InProgress,
        context: Value::Object(serde_json::Map::new()),
        ip_address: None,
        user_agent: None,
        created_at: now,
        updated_at: now,
        expires_at: now + chrono::Duration::hours(1),
        completed_at: None,
    };

    let challenge = FlowExecutor::current_challenge(&plan, &session)
        .map_err(|e| RouteError::Internal(Box::new(e)))?;

    let response = build_response(&plan, &session, challenge, None);

    // Store in memory
    SESSION_STORE
        .write()
        .await
        .insert(session_id, (plan, session));

    Ok(Json(response))
}

// ---------------------------------------------------------------------------
// GET /api/v1/flow/session/:id
// ---------------------------------------------------------------------------

/// Get the current challenge for an existing flow session.
#[endpoint]
pub async fn get_flow_session(req: &mut Request) -> Result<Json<FlowResponse>, RouteError> {
    let id: Ulid = req
        .param::<String>("id")
        .ok_or_else(|| RouteError::BadRequest("missing session id".into()))?
        .parse()
        .map_err(|_| RouteError::BadRequest("invalid session id".into()))?;

    let store = SESSION_STORE.read().await;
    let (plan, session) = store.get(&id).ok_or(RouteError::NotFound)?;

    if session.status.is_terminal() {
        // Return a FlowDone challenge for completed sessions
        let challenge = StageChallenge::FlowDone {
            redirect_to: Some("/account".into()),
        };
        let response = build_response(plan, session, challenge, None);
        return Ok(Json(response));
    }

    let challenge = FlowExecutor::current_challenge(plan, session)
        .map_err(|e| RouteError::Internal(Box::new(e)))?;

    let response = build_response(plan, session, challenge, None);

    Ok(Json(response))
}

// ---------------------------------------------------------------------------
// POST /api/v1/flow/session/:id/respond
// ---------------------------------------------------------------------------

/// Submit a response to the current stage challenge.
///
/// On success, advances to the next stage (or completes the flow) and
/// returns the new challenge.  On validation failure, returns the current
/// challenge again with error details.
#[endpoint]
pub async fn respond_flow(req: &mut Request) -> Result<Json<FlowResponse>, RouteError> {
    let id: Ulid = req
        .param::<String>("id")
        .ok_or_else(|| RouteError::BadRequest("missing session id".into()))?
        .parse()
        .map_err(|_| RouteError::BadRequest("invalid session id".into()))?;

    let input: RespondInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let mut store = SESSION_STORE.write().await;
    let (plan, session) = store.get_mut(&id).ok_or(RouteError::NotFound)?;

    if session.status.is_terminal() {
        return Err(RouteError::BadRequest("flow session is no longer active".into()));
    }

    // Process the response through the executor
    let (outcome, updated_context) = FlowExecutor::process_response(plan, session, input.response)
        .map_err(|e| RouteError::Internal(Box::new(e)))?;

    // Update the session context
    session.context = updated_context;
    session.updated_at = Utc::now();

    match outcome {
        StageOutcome::Continue => {
            // Advance to the next stage
            if FlowExecutor::has_next_stage(plan, session) {
                session.current_stage_index += 1;

                let challenge = FlowExecutor::current_challenge(plan, session)
                    .map_err(|e| RouteError::Internal(Box::new(e)))?;

                let response = build_response(plan, session, challenge, None);
                Ok(Json(response))
            } else {
                // Flow is done
                session.status = FlowSessionStatus::Completed;
                session.completed_at = Some(Utc::now());

                let challenge = StageChallenge::FlowDone {
                    redirect_to: Some("/account".into()),
                };
                // Stage index points past the last stage to indicate completion
                session.current_stage_index = plan.stages.len();
                let response = build_response(plan, session, challenge, None);
                Ok(Json(response))
            }
        }
        StageOutcome::Retry { errors } => {
            // Re-display the current challenge with validation errors
            let challenge = FlowExecutor::current_challenge(plan, session)
                .map_err(|e| RouteError::Internal(Box::new(e)))?;

            let response = build_response(plan, session, challenge, Some(errors));
            Ok(Json(response))
        }
        StageOutcome::Done { redirect_to } => {
            // The stage itself decided the flow is done (e.g. consent denied)
            session.status = FlowSessionStatus::Completed;
            session.completed_at = Some(Utc::now());

            let challenge = StageChallenge::FlowDone { redirect_to };
            session.current_stage_index = plan.stages.len();
            let response = build_response(plan, session, challenge, None);
            Ok(Json(response))
        }
    }
}
