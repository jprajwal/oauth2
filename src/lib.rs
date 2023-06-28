mod auth_code;
mod auth_token_error;
mod client_cred_grant_token_request;
mod owner_password_token_request;
mod refresh_token_request;
mod utils;

pub use auth_code::{
    AuthCodeAccessTokenRequest, AuthCodeError, AuthCodeErrorKind, AuthCodeRequest, AuthCodeToken,
};
pub use auth_token_error::{AuthTokenError, AuthTokenErrorKind};
pub use client_cred_grant_token_request::ClientCredentialsGrantAuthTokenRequest;
pub use owner_password_token_request::OwnerPasswordAccessTokenRequest;
pub use refresh_token_request::RefreshTokenRequest;

pub trait Token {
    fn set_refresh_token(self, refresh_token: String) -> Self;
    fn set_exprires_in(self, expires_in: u32) -> Self;
    fn set_scope(self, scopes: Vec<String>) -> Self;
    fn access_token(&self) -> String;
    fn refresh_token(&self) -> Option<String>;
    fn token_type(&self) -> String;
    fn scopes(&self) -> Option<Vec<String>>;
    fn is_valid(&self) -> bool;
}
