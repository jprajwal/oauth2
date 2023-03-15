#![allow(dead_code)]

use std::collections::HashMap;
use std::default::Default;
use std::iter::IntoIterator;
use url::{ParseError, Url};

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

    fn get_url(&self) -> Result<String, ParseError> {
        let mut url = Url::parse(self.auth_url.as_str())?;
        let mut queries = url.query_pairs_mut();
        queries
            .append_pair("client_id", self.client_id.as_str())
            .append_pair("response_type", self.response_type.as_str());
        if let Some(ref redirect_url) = self.redirect_url {
            queries.append_pair("redirect_uri", redirect_url.as_str());
        }
        if let Some(ref state) = self.state {
            queries.append_pair("state", state.as_str());
        }
        if let Some(ref scopes) = self.scope {
            let result = utils::join(scopes.iter().map(|s| s.as_str()), ' ');
            queries.append_pair("scope", result.as_str());
        }
        if let Some(ref extras) = self.extras {
            queries.extend_pairs(extras);
        }
        let url = queries.finish();
        Ok(url.to_string())
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
}
