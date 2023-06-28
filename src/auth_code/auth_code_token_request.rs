// use serde::de::DeserializeOwned;
// use std::error::Error;
use crate::utils;

#[derive(Debug)]
pub struct AuthCodeAccessTokenRequest {
    code: String,
    redirect_url: String,
    client_id: String,
    client_secret: Option<String>,
    scope: Option<Vec<String>>,
    extras: Option<Vec<(String, String)>>,
}

impl AuthCodeAccessTokenRequest {
    pub fn new(code: String, redirect_url: String, client_id: String) -> Self {
        AuthCodeAccessTokenRequest {
            code,
            redirect_url,
            client_id,
            client_secret: None,
            scope: None,
            extras: None,
        }
    }

    pub fn extra_params(&mut self, k: String, v: String) {
        self.extras.get_or_insert(Vec::new()).push((k, v));
    }

    pub fn add_scope(&mut self, scope: String) {
        self.scope.get_or_insert(vec![]).push(scope);
    }

    pub fn add_scopes<I>(&mut self, scopes: I)
    where
        I: IntoIterator<Item = String>,
    {
        if self.scope.is_none() {
            self.scope = Some(vec![]);
        }
        utils::append_to_vec(self.scope.as_mut().unwrap(), scopes);
    }

    pub fn set_client_secret(&mut self, secret: String) {
        self.client_secret = Some(secret);
    }

    pub fn get_headers(&self) -> Vec<(String, String)> {
        return vec![(
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        )];
    }

    pub fn get_request_params_as_vec(&self) -> Vec<(String, String)> {
        let mut params = vec![
            ("grant_type".into(), "authorization_code".into()),
            ("code".into(), self.code.clone()),
            ("redirect_uri".into(), self.redirect_url.clone()),
            ("client_id".into(), self.client_id.clone()),
        ];
        if let Some(ref client_secret) = self.client_secret {
            params.push(("client_secret".into(), client_secret.clone()));
        }
        let scope_as_string: String;
        if let Some(ref scopes) = self.scope {
            scope_as_string = scopes.join(" ");
            params.push(("scope".into(), scope_as_string));
        }
        if let Some(ref extras) = self.extras {
            utils::append_to_vec(&mut params, extras.iter().map(|a| a.clone()));
        }
        return params;
    }

    /*
    pub fn req_body(&self) -> Result<String, Box<dyn Error>> {
        let mut params = vec![("grant_type", self.grant_type.as_str())];
        if let Some(ref code) = self.code {
            params.push(("code", code));
        }
        if let Some(ref redirect_url) = self.redirect_url {
            params.push(("redirect_uri", redirect_url.as_str()));
        }
        if let Some(ref client_id) = self.client_id {
            params.push(("client_id", client_id.as_str()));
        }
        if let Some(ref client_secret) = self.client_secret {
            params.push(("client_secret", client_secret.as_str()));
        }
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

    pub fn get_token<'a, T, R>(
        &self,
        requester: R,
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
        let (status_code, response) = requester
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
                    serde_json::from_str(response.as_str()).map_err(|e| e.to_string())?;
                return Err(Box::new(error));
            }
        }
    }
    */
}
#[cfg(test)]
mod tests {
    /*
    use super::*;
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
