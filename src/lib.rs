mod auth_code;
mod auth_token_error;
mod client_cred_grant_token_request;
mod code_verifier;
mod owner_password_token_request;
mod refresh_token_request;
mod utils;

pub use auth_code::{
    AuthCodeAccessTokenRequest, AuthCodeError, AuthCodeErrorKind, AuthCodeRequest, AuthCodeToken,
};
pub use auth_token_error::{AuthTokenError, AuthTokenErrorKind};
pub use client_cred_grant_token_request::ClientCredentialsGrantAuthTokenRequest;
pub use code_verifier::{ChallengMethod, CodeVerifier};
pub use owner_password_token_request::OwnerPasswordAccessTokenRequest;
pub use refresh_token_request::RefreshTokenRequest;

pub trait Token {
    fn set_refresh_token(&mut self, refresh_token: String);
    fn set_exprires_in(&mut self, expires_in: u32);
    fn set_scope(&mut self, scopes: Vec<String>);
    fn access_token(&self) -> String;
    fn refresh_token(&self) -> Option<String>;
    fn token_type(&self) -> String;
    fn scopes(&self) -> Option<String>;
    fn is_valid(&self) -> bool;
}
