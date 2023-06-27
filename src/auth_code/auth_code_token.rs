use crate::utils;
use crate::Token;
use serde::{self, Deserialize, Serialize};
use std::cmp::PartialEq;
use std::time::SystemTime;

#[derive(Debug, Eq, Deserialize, Serialize)]
pub struct AuthCodeToken {
    access_token: String,
    token_type: String,
    refresh_token: Option<String>,
    expires_in: Option<u32>,
    #[serde(deserialize_with = "utils::deserialize_space_sep_vec")]
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
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
