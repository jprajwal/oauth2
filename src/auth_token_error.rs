use serde::{self, Deserialize, Serialize};
use std::error::Error;
use std::fmt::Display;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthTokenErrorKind {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
}

impl Display for AuthTokenErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use AuthTokenErrorKind::*;
        write!(
            f,
            "AuthCodeErrorKind::{}",
            match self {
                InvalidRequest => "InvalidRequest",
                InvalidClient => "InvalidClient",
                InvalidGrant => "InvalidGrant",
                UnauthorizedClient => "UnauthorizedClient",
                UnsupportedGrantType => "UnsupportedGrantType",
                InvalidScope => "InvalidScope",
            }
        )
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AuthTokenError {
    error: AuthTokenErrorKind,
    error_description: Option<String>,
    error_ui: Option<String>,
}

impl Error for AuthTokenError {}

impl Display for AuthTokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AuthTokenError(error = {}, error_description = {}, error_ui = {})",
            self.error,
            self.error_description
                .as_ref()
                .unwrap_or(&String::default()),
            self.error_ui.as_ref().unwrap_or(&String::default())
        )
    }
}
