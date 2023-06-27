use serde::de::DeserializeOwned;
use serde::{self, Deserialize, Serialize};
use serde_json;
use serde_urlencoded;
use std::boxed::Box;
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Display;

mod auth_code;
mod utils;

pub use auth_code::{
    AuthCodeAccessTokenRequest, AuthCodeError, AuthCodeErrorKind, AuthCodeRequest, AuthCodeToken,
};

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

pub trait HttpAdapter {
    fn post(
        &self,
        url: String,
        body: String,
        headers: Vec<(String, String)>,
    ) -> Result<(u16, String), Box<dyn Error>>;

    fn get(
        &self,
        url: String,
        headers: Vec<(String, String)>,
    ) -> Result<(u16, String), Box<dyn Error>>;
}

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

#[derive(Debug)]
pub struct OwnerPasswordAccessTokenRequest {
    token_url: String,
    username: String,
    password: String,
    extras: Option<HashMap<String, String>>,
    scope: Option<Vec<String>>,
}

impl OwnerPasswordAccessTokenRequest {
    pub fn new(token_url: String, username: String, password: String) -> Self {
        OwnerPasswordAccessTokenRequest {
            token_url,
            username,
            password,
            extras: None,
            scope: None,
        }
    }

    pub fn set_scope(mut self, scopes: Vec<String>) -> Self {
        self.scope = Some(scopes);
        self
    }

    pub fn extra_params(mut self, k: String, v: String) -> Self {
        self.extras.get_or_insert(HashMap::new()).insert(k, v);
        self
    }

    pub fn get_headers(&self) -> Vec<(String, String)> {
        return vec![(
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        )];
    }

    pub fn req_body(&self) -> Result<String, Box<dyn Error>> {
        let mut params = vec![
            ("grant_type", "password"),
            ("username", self.username.as_str()),
            ("password", self.password.as_str()),
        ];
        let scope_as_string: String;
        if let Some(ref scopes) = self.scope {
            scope_as_string = scopes.join(" ");
            params.push(("scope", scope_as_string.as_str()));
        }

        if let Some(ref extras) = self.extras {
            params.extend(
                extras
                    .iter()
                    .map(|(a, b)| (a.as_str(), b.as_str()))
                    .collect::<Vec<_>>(),
            );
        }
        let body = serde_urlencoded::to_string(&params).map_err(|e| e.to_string())?;
        Ok(body)
    }

    fn token_url(&self) -> Result<String, Box<dyn Error>> {
        // TODO: Validate URL
        return Ok(self.token_url.clone());
    }

    pub fn get_token<T, R>(
        &self,
        http: R,
        additional_headers: Option<Vec<(String, String)>>,
    ) -> Result<T, Box<dyn Error>>
    where
        T: Token + DeserializeOwned,
        R: HttpAdapter,
    {
        let url = self.token_url().map_err(|e| e.to_string())?;
        let form_data = self.req_body().map_err(|e| e.to_string())?;
        let mut headers = self.get_headers();
        match additional_headers {
            Some(header) => headers.extend(header),
            None => {}
        }
        let (status_code, response) = http
            .post(url, form_data, headers)
            .map_err(|e| e.to_string())?;
        match status_code {
            status if status >= 200 && status < 300 => {
                let token: T =
                    serde_json::from_str(response.as_str()).map_err(|e| e.to_string())?;
                return Ok(token);
            }
            _ => {
                let error: AuthTokenError =
                    serde_json::from_str(response.as_str()).map_err(|_| response.clone())?;
                return Err(Box::new(error));
            }
        }
    }
}

pub struct ClientCredentialsGrantAuthTokenRequest {
    token_url: String,
    extras: Option<HashMap<String, String>>,
    scope: Option<Vec<String>>,
}

impl ClientCredentialsGrantAuthTokenRequest {
    pub fn new(token_url: String) -> Self {
        Self {
            token_url,
            extras: None,
            scope: None,
        }
    }
    pub fn set_scope(mut self, scopes: Vec<String>) -> Self {
        self.scope = Some(scopes);
        self
    }

    pub fn extra_params(mut self, k: String, v: String) -> Self {
        self.extras.get_or_insert(HashMap::new()).insert(k, v);
        self
    }

    pub fn get_headers(&self) -> Vec<(String, String)> {
        return vec![(
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        )];
    }

    pub fn req_body(&self) -> Result<String, Box<dyn Error>> {
        let mut params = vec![("grant_type", "password")];
        let scope_as_string: String;
        if let Some(ref scopes) = self.scope {
            scope_as_string = scopes.join(" ");
            params.push(("scope", scope_as_string.as_str()));
        }
        if let Some(ref extras) = self.extras {
            params.extend(
                extras
                    .iter()
                    .map(|(a, b)| (a.as_str(), b.as_str()))
                    .collect::<Vec<_>>(),
            );
        }
        let body = serde_urlencoded::to_string(&params).map_err(|e| e.to_string())?;
        Ok(body)
    }

    fn token_url(&self) -> Result<String, Box<dyn Error>> {
        // TODO: Validate URL
        return Ok(self.token_url.clone());
    }

    pub fn get_token<T, H>(
        &self,
        http: H,
        auth_header: Vec<(String, String)>,
    ) -> Result<T, Box<dyn Error>>
    where
        T: Token + DeserializeOwned,
        H: HttpAdapter,
    {
        let url = self.token_url().map_err(|e| e.to_string())?;
        let form_data = self.req_body().map_err(|e| e.to_string())?;
        let mut headers = self.get_headers();
        headers.extend(auth_header);
        let (status_code, response) = http
            .post(url, form_data, headers)
            .map_err(|e| e.to_string())?;
        match status_code {
            status if status >= 200 && status < 300 => {
                let token: T =
                    serde_json::from_str(response.as_str()).map_err(|e| e.to_string())?;
                return Ok(token);
            }
            _ => {
                let error: AuthTokenError =
                    serde_json::from_str(response.as_str()).map_err(|_| response.clone())?;
                return Err(Box::new(error));
            }
        }
    }
}

pub struct RefreshTokenRequest {
    refresh_token_url: String,
    refresh_token: String,
    extras: Option<HashMap<String, String>>,
    scope: Option<Vec<String>>,
}

impl RefreshTokenRequest {
    pub fn new(token_url: String, refresh_token: String) -> Self {
        Self {
            refresh_token_url: token_url,
            refresh_token,
            extras: None,
            scope: None,
        }
    }

    pub fn extra_params(mut self, k: String, v: String) -> Self {
        self.extras.get_or_insert(HashMap::new()).insert(k, v);
        self
    }

    pub fn set_scope(mut self, scopes: Vec<String>) -> Self {
        self.scope = Some(scopes);
        self
    }

    pub fn get_headers(&self) -> Vec<(String, String)> {
        return vec![(
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        )];
    }

    pub fn req_body(&self) -> Result<String, Box<dyn Error>> {
        let mut params = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", self.refresh_token.as_str()),
        ];

        let scopes_as_string: String;
        if let Some(ref scopes) = self.scope {
            scopes_as_string = scopes.join(" ");
            params.push(("scope", scopes_as_string.as_str()));
        }
        if let Some(ref extras) = self.extras {
            params.extend(
                extras
                    .iter()
                    .map(|(a, b)| (a.as_str(), b.as_str()))
                    .collect::<Vec<_>>(),
            );
        }
        let body = serde_urlencoded::to_string(&params).map_err(|e| e.to_string())?;
        Ok(body)
    }

    fn token_url(&self) -> Result<String, Box<dyn Error>> {
        // TODO: Validate URL
        return Ok(self.refresh_token_url.clone());
    }

    pub fn get_token<T, H>(
        &self,
        http: H,
        additional_headers: Option<Vec<(String, String)>>,
    ) -> Result<T, Box<dyn Error>>
    where
        T: Token + DeserializeOwned,
        H: HttpAdapter,
    {
        let url = self.token_url().map_err(|e| e.to_string())?;
        let form_data = self.req_body().map_err(|e| e.to_string())?;
        let mut headers = self.get_headers();
        if let Some(header) = additional_headers {
            headers.extend(header);
        }
        let (status_code, response) = http
            .post(url, form_data, headers)
            .map_err(|e| e.to_string())?;
        match status_code {
            status if status >= 200 && status < 300 => {
                let token: T =
                    serde_json::from_str(response.as_str()).map_err(|e| e.to_string())?;
                return Ok(token);
            }
            _ => {
                let error: AuthTokenError =
                    serde_json::from_str(response.as_str()).map_err(|_| response.clone())?;
                return Err(Box::new(error));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_join() {
        assert_eq!(utils::join(["a", "b", "c"].into_iter(), ' '), "a b c");
    }

    /*
    #[derive(Debug)]
    struct TestPostRequester {
        response: String,
    }

    impl HttpAdapter for TestPostRequester {
        fn post(
            &self,
            _url: String,
            _body: String,
            _headers: Vec<(String, String)>,
        ) -> Result<(u16, String), Box<dyn Error>> {
            Ok((200, self.response.clone()))
        }

        fn get(
            &self,
            _url: String,
            _headers: Vec<(String, String)>,
        ) -> Result<(u16, String), Box<dyn Error>> {
            Err(String::default().into())
        }
    }

    #[test]
    fn test_auth_code_get_token() {
        let requester = TestPostRequester {
            response: String::from(
                r#"{
                    "access_token": "test_token",
                    "refresh_token": "test_refresh_token",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                    "scope": "test_scope test_another_scope"
                }"#,
            ),
        };
        let token_request = AuthCodeAccessTokenRequest::new("test_url".into(), "code".into());
        let expected_token = AuthCodeToken {
            access_token: "test_token".into(),
            token_type: "Bearer".into(),
            refresh_token: Some("test_refresh_token".into()),
            expires_in: Some(3600),
            scope: Some(vec![
                "test_scope".to_owned(),
                "test_another_scope".to_owned(),
            ]),
            generated_time: SystemTime::now(),
        };
        let token: AuthCodeToken = token_request.get_token(requester, None).unwrap();
        assert_eq!(token, expected_token);
    }
    */
}
