use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use zedr_protocol::ErrorResponse;

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Not found")]
    NotFound,

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Forbidden")]
    Forbidden,

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Unprocessable: {0}")]
    Unprocessable(String),

    #[error("Too many failed attempts, retry after {0} seconds")]
    TooManyAttempts(u64),

    #[error("Internal server error: {0}")]
    InternalError(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let retry_after = match self {
            AppError::TooManyAttempts(seconds) => Some(seconds),
            _ => None,
        };

        let (status, error_message) = match self {
            AppError::Database(ref e) => {
                tracing::error!("Database error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Database error")
            }
            AppError::Config(ref msg) => {
                tracing::error!("Configuration error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "Configuration error")
            }
            AppError::NotFound => (StatusCode::NOT_FOUND, "Not found"),
            AppError::BadRequest(ref msg) => (StatusCode::BAD_REQUEST, msg.as_str()),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized"),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "Forbidden"),
            AppError::Conflict(ref msg) => (StatusCode::CONFLICT, msg.as_str()),
            AppError::Unprocessable(ref msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg.as_str()),
            AppError::TooManyAttempts(_) => (StatusCode::TOO_MANY_REQUESTS, "Too many failed attempts"),
            AppError::InternalError(ref msg) => {
                tracing::error!("Internal server error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
        };

        let body = Json(ErrorResponse {
            error: error_message.to_string(),
        });

        let mut response = (status, body).into_response();
        if let Some(seconds) = retry_after {
            response.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from(seconds));
        }
        response
    }
}

pub type Result<T, E = AppError> = std::result::Result<T, E>;

/// Why something an agent sent was turned down: for what it says, or because the server failed while reading it
pub enum Refusal {
    Invalid(String),
    Failed(AppError),
}

impl From<String> for Refusal {
    fn from(reason: String) -> Self {
        Refusal::Invalid(reason)
    }
}

impl From<AppError> for Refusal {
    fn from(error: AppError) -> Self {
        Refusal::Failed(error)
    }
}

impl From<sqlx::Error> for Refusal {
    fn from(error: sqlx::Error) -> Self {
        Refusal::Failed(error.into())
    }
}
