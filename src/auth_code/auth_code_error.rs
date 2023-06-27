use serde::{self, Deserialize, Serialize};
use std::error::Error;
use std::fmt::Display;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthCodeErrorKind {
    InvalidRequest,
    UnauthorizedClient,
    AccessDenied,
    UnsupportedResponseType,
    InvalidScope,
    ServerError,
    TemporarilyUnavailable,
}

impl Display for AuthCodeErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use AuthCodeErrorKind::*;
        write!(
            f,
            "AuthErrorKind::{}",
            match self {
                InvalidRequest => "InvalidRequest",
                UnauthorizedClient => "UnauthorizedClient",
                AccessDenied => "AccessDenied",
                UnsupportedResponseType => "UnsupportedResponseType",
                InvalidScope => "InvalidScope",
                ServerError => "ServerError",
                TemporarilyUnavailable => "TemporarilyUnavailable",
            }
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthCodeError {
    error: AuthCodeErrorKind,
    error_description: Option<String>,
    error_uri: Option<String>,
    state: Option<String>,
}

impl Display for AuthCodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AuthError(error = {}, error_description = {}, error_url = {}, state = {})",
            self.error,
            self.error_description
                .as_ref()
                .unwrap_or(&String::default()),
            self.error_uri.as_ref().unwrap_or(&String::default()),
            self.state.as_ref().unwrap_or(&String::default()),
        )
    }
}

impl Error for AuthCodeError {}
