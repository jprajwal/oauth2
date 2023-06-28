use crate::Token;
use serde::{self, Deserialize, Deserializer, Serialize};
use std::cmp::PartialEq;
use std::fmt;
use std::time::SystemTime;

#[derive(Debug, Eq, PartialEq, Serialize, Clone)]
enum Scope {
    Array(Vec<String>),
    Str(String),
}

struct MyVisitor;

impl<'de> serde::de::Visitor<'de> for MyVisitor {
    type Value = Scope;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "Failed to parse scopes")?;
        Ok(())
    }

    fn visit_seq<A>(self, mut value: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut vector: Vec<String> = Vec::with_capacity(value.size_hint().unwrap_or(0));
        loop {
            let element = value.next_element()?;
            match element {
                Some(data) => vector.push(data),
                None => break,
            }
        }
        Ok(Scope::Array(vector))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Scope::Str(String::from(value)))
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Scope::Str(v))
    }
}

impl<'de> serde::de::Deserialize<'de> for Scope {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let visitor = MyVisitor {};
        d.deserialize_any(visitor)
    }
}

#[derive(Debug, Eq, Deserialize, Serialize)]
pub struct AuthCodeToken {
    access_token: String,
    token_type: String,
    refresh_token: Option<String>,
    expires_in: Option<u32>,
    // #[serde(deserialize_with = "utils::deserialize_scope")]
    scope: Option<Scope>,
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
    fn set_refresh_token(&mut self, refresh_token: String) {
        self.refresh_token = Some(refresh_token);
    }

    fn set_exprires_in(&mut self, expires_in: u32) {
        self.expires_in = Some(expires_in);
    }

    fn set_scope(&mut self, scopes: Vec<String>) {
        self.scope = Some(Scope::Str(scopes.join(" ")));
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

    fn scopes(&self) -> Option<String> {
        self.scope.clone().map(|v| match v {
            Scope::Array(ref arr) => arr.join(" "),
            Scope::Str(ref s) => s.clone(),
        })
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
    use serde_json;
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

    #[test]
    fn test_auth_token_deserializtion_scope_is_space_seperated_string() {
        let json_data = r#"{
    "access_token": "test_token",
    "refresh_token": "test_refresh_token",
    "expires_in": 3600,
    "token_type": "Bearer",
    "scope": "test_scope test_another_scope"
}"#;
        let token: AuthCodeToken = serde_json::from_str(json_data).unwrap();
        assert_eq!(
            token.scopes(),
            Some(String::from("test_scope test_another_scope"))
        );
    }

    #[test]
    fn test_auth_token_deserializtion_scope_is_array() {
        let json_data = r#"{
            "access_token": "test_token",
            "refresh_token": "test_refresh_token",
            "expires_in": 3600,
            "token_type": "Bearer",
            "scope": ["test_scope", "test_another_scope"]
        }"#;
        let token: AuthCodeToken = serde_json::from_str(json_data).unwrap();
        assert_eq!(
            token.scopes(),
            Some(String::from("test_scope test_another_scope"))
        );
    }

    #[test]
    fn test_auth_token_deserializtion_scope_is_absent() {
        let json_data = r#"{
            "access_token": "test_token",
            "refresh_token": "test_refresh_token",
            "expires_in": 3600,
            "token_type": "Bearer"
        }"#;
        let token: AuthCodeToken = serde_json::from_str(json_data).unwrap();
        assert_eq!(token.scopes(), None);
    }
}
