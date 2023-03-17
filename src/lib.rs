#![allow(dead_code)]

use serde::{self, Deserialize, Serialize};
use serde_json;
use serde_urlencoded;
use std::collections::HashMap;

#[derive(Default, Debug, PartialEq, Eq)]
struct AuthCodeRequest {
    auth_url: String,
    client_id: String,
    response_type: String,
    redirect_url: Option<String>,
    scope: Option<Vec<String>>,
    state: Option<String>,
    extras: Option<HashMap<String, String>>,
}

impl AuthCodeRequest {
    fn new(auth_url: String, client_id: String, response_type: String) -> Self {
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

    fn set_redirect_url(mut self, redirect_url: String) -> Self {
        self.redirect_url = Some(redirect_url);
        self
    }

    fn add_scope(mut self, scope: String) -> Self {
        self.scope.get_or_insert(vec![]).push(scope);
        self
    }

    fn add_scopes<I>(mut self, scopes: I) -> Self
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

    fn set_state(mut self, state: String) -> Self {
        self.state = Some(state);
        self
    }

    fn extra_params(mut self, k: String, v: String) -> Self {
        self.extras.get_or_insert(HashMap::new()).insert(k, v);
        self
    }

    fn get_url(&self) -> Result<String, ()> {
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
                .map_err(|_| ())?
                .as_str(),
        );
        Ok(url.to_string())
    }
}

#[derive(Debug)]
struct AuthCodeAccessTokenRequest {
    token_url: String,
    grant_type: String,
    code: String,
    redirect_url: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    extras: Option<HashMap<String, String>>,
}

impl AuthCodeAccessTokenRequest {
    fn new(token_url: String, grant_type: String, code: String) -> Self {
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

    fn extra_params(mut self, k: String, v: String) -> Self {
        self.extras.get_or_insert(HashMap::new()).insert(k, v);
        self
    }

    fn set_redirect_url(mut self, redirect_url: String) -> Self {
        self.redirect_url = Some(redirect_url);
        self
    }

    fn set_client_id(mut self, client_id: String) -> Self {
        self.client_id = Some(client_id);
        self
    }

    fn set_client_secret(mut self, client_secret: String) -> Self {
        self.client_secret = Some(client_secret);
        self
    }

    fn token_url(&mut self) -> Result<String, ()> {
        // TODO: Validate URL
        return Ok(self.token_url.clone());
    }

    fn req_body(&mut self) -> Result<String, ()> {
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
        let body = serde_urlencoded::to_string(&params).map_err(|_| ())?;
        Ok(body)
    }

    fn get_token<T: PostRequest>(&mut self, requester: T) -> Result<AuthCodeToken, ()> {
        let url = self.token_url().map_err(|_| ())?;
        let form_data = self.req_body().map_err(|_| ())?;
        let response = requester.post(url, form_data).map_err(|_| ())?;
        let token: AuthCodeToken = serde_json::from_str(response.as_str()).map_err(|_| ())?;
        return Ok(token);
    }
}

trait Token {
    fn set_refresh_token(self, refresh_token: String) -> Self;
    fn set_exprires_in(self, expires_in: u32) -> Self;
    fn set_scope(self, scopes: Vec<String>) -> Self;
    fn access_token(&self) -> String;
    fn refresh_token(&self) -> Option<String>;
    fn token_type(&self) -> String;
    fn scopes(&self) -> Option<Vec<String>>;
    fn is_valid(&self) -> bool;
}

#[derive(Debug, Eq, PartialEq, Deserialize, Serialize)]
struct AuthCodeToken {
    access_token: String,
    token_type: String,
    refresh_token: Option<String>,
    expires_in: Option<u32>,
    scope: Option<Vec<String>>,
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
        true
    }
}

impl AuthCodeToken {
    fn new(access_token: String, token_type: String) -> Self {
        AuthCodeToken {
            access_token,
            token_type,
            refresh_token: None,
            expires_in: None,
            scope: None,
        }
    }
}

trait PostRequest {
    fn post(&self, url: String, body: String) -> Result<String, ()>;
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
        fn post(&self, _url: String, _body: String) -> Result<String, ()> {
            Ok(self.response.clone())
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
        };
        assert_eq!(token_request.get_token(requester), Ok(expected_token));
    }
}
