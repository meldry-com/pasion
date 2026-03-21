use hyper::{StatusCode, header};
use pasion_salvo_utils::record_error;
use salvo::prelude::*;
use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;

pub mod login;
pub mod login_sso_complete;
pub mod login_sso_redirect;
pub mod logout;
pub mod logout_all;
pub mod refresh;

#[derive(Debug, Serialize)]
struct MatrixError {
    errcode: &'static str,
    error: &'static str,
    #[serde(skip)]
    status: StatusCode,
}

impl Scribe for MatrixError {
    fn render(self, res: &mut Response) {
        res.status_code(self.status);
        res.render(Json(serde_json::json!({
            "errcode": self.errcode,
            "error": self.error,
        })));
    }
}

#[derive(Debug, Error)]
pub enum MatrixJsonBodyRejection {
    #[error("Invalid Content-Type header: expected application/json")]
    InvalidContentType,

    #[error("Invalid Content-Type header: expected application/json, got {0}")]
    ContentTypeNotJson(mime::Mime),

    #[error("Failed to read request body")]
    BodyReadError(String),

    #[error("Invalid JSON document")]
    Json(#[from] serde_json::Error),
}

impl Scribe for MatrixJsonBodyRejection {
    fn render(self, res: &mut Response) {
        let sentry_event_id = record_error!(self, !);
        let response = match self {
            Self::InvalidContentType | Self::ContentTypeNotJson(_) => MatrixError {
                errcode: "M_NOT_JSON",
                error: "Invalid Content-Type header: expected application/json",
                status: StatusCode::BAD_REQUEST,
            },

            Self::BodyReadError(ref msg) if msg.contains("length limit") => MatrixError {
                errcode: "M_TOO_LARGE",
                error: "Request body too large",
                status: StatusCode::PAYLOAD_TOO_LARGE,
            },

            Self::BodyReadError(_) => MatrixError {
                errcode: "M_UNKNOWN",
                error: "Failed to read request body",
                status: StatusCode::BAD_REQUEST,
            },

            Self::Json(ref err) if err.is_data() => MatrixError {
                errcode: "M_BAD_JSON",
                error: "JSON fields are not valid",
                status: StatusCode::BAD_REQUEST,
            },

            Self::Json(_) => MatrixError {
                errcode: "M_NOT_JSON",
                error: "Body is not a valid JSON document",
                status: StatusCode::BAD_REQUEST,
            },
        };

        response.render(res);

        // Add Sentry event ID header if available
        if let Some(event_id) = sentry_event_id {
            event_id.write_to_response(res);
        }
    }
}

/// Parse a Matrix JSON body from the request.
///
/// Matrix spec says it's optional to send a Content-Type header, so we
/// only check it if it's present.
pub async fn parse_matrix_json<T: DeserializeOwned>(
    req: &mut Request,
) -> Result<T, MatrixJsonBodyRejection> {
    // Matrix spec says it's optional to send a Content-Type header, so we
    // only check it if it's present
    if let Some(content_type) = req.headers().get(header::CONTENT_TYPE) {
        let Ok(content_type) = content_type.to_str() else {
            return Err(MatrixJsonBodyRejection::InvalidContentType);
        };

        let Ok(mime) = content_type.parse::<mime::Mime>() else {
            return Err(MatrixJsonBodyRejection::InvalidContentType);
        };

        let is_json_content_type = mime.type_() == "application"
            && (mime.subtype() == "json" || mime.suffix().is_some_and(|name| name == "json"));

        if !is_json_content_type {
            return Err(MatrixJsonBodyRejection::ContentTypeNotJson(mime));
        }
    }

    let bytes = req
        .payload()
        .await
        .map_err(|e| MatrixJsonBodyRejection::BodyReadError(e.to_string()))?;

    let value: T = serde_json::from_slice(bytes)?;

    Ok(value)
}

/// Try to parse an optional Matrix JSON body from the request.
///
/// Returns `Ok(None)` if there is no Content-Type header and the body is empty.
pub async fn parse_optional_matrix_json<T: DeserializeOwned>(
    req: &mut Request,
) -> Result<Option<T>, MatrixJsonBodyRejection> {
    if req.headers().contains_key(header::CONTENT_TYPE) {
        // If there is a Content-Type header, handle it as normal
        let result = parse_matrix_json(req).await?;
        return Ok(Some(result));
    }

    // Else, we poke at the body, and deserialize it only if it's JSON
    let bytes = req
        .payload()
        .await
        .map_err(|e| MatrixJsonBodyRejection::BodyReadError(e.to_string()))?;

    if bytes.is_empty() {
        return Ok(None);
    }

    let value: T = serde_json::from_slice(bytes)?;

    Ok(Some(value))
}
