// #![allow(dead_code)]

use serde::{self, Deserialize, Serialize};
use serde_json;
use serde_urlencoded;
use std::boxed::Box;
use std::cmp::PartialEq;
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Display;
use std::time::SystemTime;

#[derive(Default, Debug, PartialEq, Eq)]
pub struct AuthCodeRequest {
    auth_url: String,
    client_id: String,
    response_type: String,
    redirect_url: Option<String>,
    scope: Option<Vec<String>>,
    state: Option<String>,
    extras: Option<HashMap<String, String>>,
}

impl AuthCodeRequest {
    pub fn new(auth_url: String, client_id: String, response_type: String) -> Self {
        Self {
            auth_url,
            client_id,
            response_type,
            redirect_url: None,
            scope: None,
            state: None,
            extras: None,
        }
    }

    pub fn set_redirect_url(mut self, redirect_url: String) -> Self {
        self.redirect_url = Some(redirect_url);
        self
    }

    pub fn add_scope(mut self, scope: String) -> Self {
        self.scope.get_or_insert(vec![]).push(scope);
        self
    }

    pub fn add_scopes<I>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = String>,
    {
        if self.scope.is_none() {
            self.scope = Some(vec![]);
        }
        scopes.into_iter().for_each(|scope| {
            self.scope.as_mut().unwrap().push(scope);
        });
        self
    }

    pub fn set_state(mut self, state: String) -> Self {
        self.state = Some(state);
        self
    }

    pub fn extra_params(mut self, k: String, v: String) -> Self {
        self.extras.get_or_insert(HashMap::new()).insert(k, v);
        self
    }

    pub fn get_url(&self) -> Result<String, Box<dyn Error>> {
        let mut url: String = self.auth_url.clone();

        let result: String;
        let mut params = vec![
            ("client_id", self.client_id.as_str()),
            ("response_type", self.response_type.as_str()),
        ];
        if let Some(ref redirect_url) = self.redirect_url {
            params.push(("redirect_uri", redirect_url.as_str()));
        }
        if let Some(ref state) = self.state {
            params.push(("state", state.as_str()));
        }
        if let Some(ref scopes) = self.scope {
            result = utils::join(scopes.iter().map(|s| s.as_str()), ' ');
            params.push(("scope", result.as_str()));
        }
        if let Some(ref extras) = self.extras {
            params.extend(
                extras
                    .iter()
                    .map(|(a, b)| (a.as_str(), b.as_str()))
                    .collect::<Vec<_>>(),
            );
        }

        url.push('?');
        url.push_str(
            serde_urlencoded::to_string(params)
                .map_err(|e| e.to_string())?
                .as_str(),
        );
        Ok(url.to_string())
    }
}

#[derive(Debug)]
pub struct AuthCodeAccessTokenRequest {
    token_url: String,
    grant_type: String,
    code: String,
    redirect_url: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    extras: Option<HashMap<String, String>>,
}

impl AuthCodeAccessTokenRequest {
    pub fn new(token_url: String, grant_type: String, code: String) -> Self {
        AuthCodeAccessTokenRequest {
            token_url,
            grant_type,
            code,
            redirect_url: None,
            client_id: None,
            client_secret: None,
            extras: None,
        }
    }

    pub fn extra_params(mut self, k: String, v: String) -> Self {
        self.extras.get_or_insert(HashMap::new()).insert(k, v);
        self
    }

    pub fn set_redirect_url(mut self, redirect_url: String) -> Self {
        self.redirect_url = Some(redirect_url);
        self
    }

    pub fn set_client_id(mut self, client_id: String) -> Self {
        self.client_id = Some(client_id);
        self
    }

    pub fn set_client_secret(mut self, client_secret: String) -> Self {
        self.client_secret = Some(client_secret);
        self
    }

    fn token_url(&self) -> Result<String, Box<dyn Error>> {
        // TODO: Validate URL
        return Ok(self.token_url.clone());
    }

    fn req_body(&self) -> Result<String, Box<dyn Error>> {
        let mut params = vec![
            ("grant_type", self.grant_type.as_str()),
            ("code", self.code.as_str()),
        ];
        if let Some(ref redirect_url) = self.redirect_url {
            params.push(("redirect_uri", redirect_url.as_str()));
        }
        if let Some(ref client_id) = self.client_id {
            params.push(("client_id", client_id.as_str()));
        }
        if let Some(ref client_secret) = self.client_secret {
            params.push(("client_secret", client_secret.as_str()));
        }
        let body = serde_urlencoded::to_string(&params).map_err(|e| e.to_string())?;
        Ok(body)
    }

    pub fn get_token<T: PostRequest>(&self, requester: T) -> Result<AuthCodeToken, Box<dyn Error>> {
        let url = self.token_url().map_err(|e| e.to_string())?;
        let form_data = self.req_body().map_err(|e| e.to_string())?;
        let (status_code, response) = requester.post(url, form_data).map_err(|e| e.to_string())?;
        match status_code {
            status if status >= 200 && status < 300 => {
                let token: AuthCodeToken =
                    serde_json::from_str(response.as_str()).map_err(|e| e.to_string())?;
                return Ok(token);
            }
            _ => {
                let error: AuthTokenError =
                    serde_json::from_str(response.as_str()).map_err(|e| e.to_string())?;
                return Err(Box::new(error));
            }
        }
    }
}

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

#[derive(Debug, Eq, Deserialize, Serialize)]
pub struct AuthCodeToken {
    access_token: String,
    token_type: String,
    refresh_token: Option<String>,
    expires_in: Option<u32>,
    scope: Option<Vec<String>>,
    #[serde(skip, default = "SystemTime::now")]
    generated_time: SystemTime,
}

impl PartialEq for AuthCodeToken {
    fn eq(&self, other: &Self) -> bool {
        self.access_token == other.access_token
            && self.token_type == other.token_type
            && self.refresh_token == other.refresh_token
            && self.expires_in == other.expires_in
            && self.scope == other.scope
    }
}

impl Token for AuthCodeToken {
    fn set_refresh_token(mut self, refresh_token: String) -> Self {
        self.refresh_token = Some(refresh_token);
        self
    }

    fn set_exprires_in(mut self, expires_in: u32) -> Self {
        self.expires_in = Some(expires_in);
        self
    }

    fn set_scope(mut self, scopes: Vec<String>) -> Self {
        self.scope = Some(scopes);
        self
    }

    fn access_token(&self) -> String {
        self.access_token.clone()
    }

    fn refresh_token(&self) -> Option<String> {
        self.refresh_token.clone()
    }

    fn token_type(&self) -> String {
        self.token_type.clone()
    }

    fn scopes(&self) -> Option<Vec<String>> {
        self.scope.clone()
    }

    fn is_valid(&self) -> bool {
        match self.expires_in {
            Some(expires_in) => {
                match self.generated_time.elapsed() {
                    Ok(elapsed) => (elapsed.as_secs() as u32) < expires_in,
                    // if err, then assume that the token is valid so that the
                    // user can try accessing the protected resource using the
                    // current token.
                    Err(_) => true,
                }
            }
            // if None, then the auth server did not provide the expiration
            // info. So, there is no other choice but to use the access token
            // and try to access the protected resource.
            None => true,
        }
    }
}

impl AuthCodeToken {
    pub fn new(access_token: String, token_type: String) -> Self {
        AuthCodeToken {
            access_token,
            token_type,
            refresh_token: None,
            expires_in: None,
            scope: None,
            generated_time: SystemTime::now(),
        }
    }
}

pub trait PostRequest {
    fn post(&self, url: String, body: String) -> Result<(u16, String), Box<dyn Error>>;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthCodeResponse {
    code: String,
    state: Option<String>,
}

impl AuthCodeResponse {
    pub fn new(code: String) -> Self {
        AuthCodeResponse { code, state: None }
    }

    pub fn set_state(mut self, state: String) -> Self {
        self.state = Some(state);
        self
    }

    pub fn get_code(&self) -> String {
        self.code.clone()
    }

    pub fn get_state(&self) -> Option<String> {
        self.state.clone()
    }
}

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

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum AuthTokenErrorKind {
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

mod utils {
    pub fn join<'a, I, T>(mut str_iter: I, sep: char) -> String
    where
        I: Iterator<Item = &'a T>,
        T: AsRef<str> + 'a + ?Sized,
    {
        let mut result = String::default();
        if let Some(val) = str_iter.next() {
            result.push_str(val.as_ref());
        }
        str_iter.for_each(|chunk| {
            result.push(sep);
            result.push_str(chunk.as_ref());
        });
        return result;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn test_default() {
        let def = AuthCodeRequest::default();
        assert_eq!(
            def,
            AuthCodeRequest {
                auth_url: "".into(),
                client_id: "".into(),
                response_type: "".into(),
                redirect_url: None,
                scope: None,
                state: None,
                extras: None
            }
        );
    }

    #[test]
    fn test_new() {
        let new = AuthCodeRequest::new(
            "test_url".into(),
            "test_id".into(),
            "test_response_type".into(),
        );
        assert_eq!(
            new,
            AuthCodeRequest {
                auth_url: String::from("test_url"),
                client_id: String::from("test_id"),
                response_type: String::from("test_response_type"),
                redirect_url: None,
                scope: None,
                state: None,
                extras: None
            }
        )
    }

    #[test]
    fn test_set_redirect_url() {
        let mut new = AuthCodeRequest::new("".into(), "".into(), "".into());
        new = new.set_redirect_url("test_redirect_url".into());
        assert!(new.redirect_url == Some(String::from("test_redirect_url")));
    }

    #[test]
    fn test_join() {
        assert_eq!(utils::join(["a", "b", "c"].into_iter(), ' '), "a b c");
    }

    #[test]
    fn test_google_auth_request_url() {
        let request = AuthCodeRequest::new(
            "https://accounts.google.com/o/oauth2/v2/auth".into(),
            "test_id".into(),
            "code".into(),
        );
        let request = request
            .add_scope("https://www.googleapis.com/auth/drive.metadata.readonly".into())
            .add_scope("https://www.googleapis.com/auth/drive.metadata.writeonly".into())
            .extra_params("access_type".into(), "offline".into())
            .extra_params("include_granted_scopes".into(), "true".into())
            .set_state("state_parameter_passthrough_value".into())
            .set_redirect_url("https://oauth2.example.com/code".into());
        let url = request.get_url().unwrap_or("".into());
        println!("url: {url}");
    }

    #[derive(Debug)]
    struct TestPostRequester {
        response: String,
    }

    impl PostRequest for TestPostRequester {
        fn post(&self, _url: String, _body: String) -> Result<(u16, String), Box<dyn Error>> {
            Ok((200, self.response.clone()))
        }
    }

    #[test]
    fn test_auth_code_get_token() {
        let requester = TestPostRequester {
            response: String::from(
                r#"{"access_token": "test_token", "refresh_token": "test_refresh_token", "expires_in": 3600, "token_type": "Bearer"}"#,
            ),
        };
        let mut token_request =
            AuthCodeAccessTokenRequest::new("test_url".into(), "code".into(), "test_code".into());
        let expected_token = AuthCodeToken {
            access_token: "test_token".into(),
            token_type: "Bearer".into(),
            refresh_token: Some("test_refresh_token".into()),
            expires_in: Some(3600),
            scope: None,
            generated_time: SystemTime::now(),
        };
        assert_eq!(token_request.get_token(requester).unwrap(), expected_token);
    }

    #[test]
    fn test_auth_token_is_valid() {
        let now = SystemTime::now();
        let token = AuthCodeToken {
            access_token: "test_token".into(),
            token_type: "Bearer".into(),
            refresh_token: Some("test_refresh_token".into()),
            expires_in: Some(3600),
            scope: None,
            generated_time: now.checked_sub(Duration::from_secs(3599)).unwrap(),
        };
        assert_eq!(token.is_valid(), true);
    }

    #[test]
    fn test_auth_token_is_valid_not_valid() {
        let now = SystemTime::now();
        let token = AuthCodeToken {
            access_token: "test_token".into(),
            token_type: "Bearer".into(),
            refresh_token: Some("test_refresh_token".into()),
            expires_in: Some(3600),
            scope: None,
            generated_time: now.checked_sub(Duration::from_secs(3600)).unwrap(),
        };
        assert_eq!(token.is_valid(), false);
    }
}
