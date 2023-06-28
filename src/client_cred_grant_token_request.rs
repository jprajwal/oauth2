use crate::utils;

pub struct ClientCredentialsGrantAuthTokenRequest {
    extras: Option<Vec<(String, String)>>,
    scope: Option<Vec<String>>,
}

impl ClientCredentialsGrantAuthTokenRequest {
    pub fn new() -> Self {
        Self {
            extras: None,
            scope: None,
        }
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

    pub fn extra_params(mut self, k: String, v: String) -> Self {
        self.extras.get_or_insert(Vec::new()).push((k, v));
        self
    }

    pub fn get_headers(&self) -> Vec<(String, String)> {
        return vec![(
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        )];
    }

    pub fn get_request_params_as_vec(&self) -> Vec<(String, String)> {
        let mut params = vec![("grant_type".into(), "client_credentials".into())];
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
