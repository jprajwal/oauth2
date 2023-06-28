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
}
