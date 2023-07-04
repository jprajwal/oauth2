use crate::utils;
use crate::OAuthParams;

pub struct ClientCredentialsGrantAuthTokenRequest {
    extras: Option<Vec<(String, String)>>,
    scope: Option<Vec<String>>,
}

impl OAuthParams for ClientCredentialsGrantAuthTokenRequest {
    fn get_grant_type(&self) -> Option<String> {
        "client_credentials".to_owned().into()
    }

    fn get_scopes_mut(&mut self) -> Option<&mut Vec<String>> {
        if self.scope.is_none() {
            self.scope = Some(vec![])
        }
        self.scope.as_mut()
    }

    fn get_scopes_ref(&self) -> Option<&Vec<String>> {
        self.scope.as_ref()
    }

    fn get_extra_params_mut(&mut self) -> Option<&mut Vec<(String, String)>> {
        if self.extras.is_none() {
            self.extras = Some(vec![])
        }
        self.extras.as_mut()
    }

    fn get_extra_params_ref(&self) -> Option<&Vec<(String, String)>> {
        self.extras.as_ref()
    }
}

impl ClientCredentialsGrantAuthTokenRequest {
    pub fn new() -> Self {
        Self {
            extras: None,
            scope: None,
        }
    }

    pub fn add_scope(&mut self, scope: String) {
        utils::add_scope(self, scope);
    }

    pub fn add_scopes<I>(&mut self, scopes: I)
    where
        I: IntoIterator<Item = String>,
    {
        utils::add_scopes(self, scopes);
    }

    pub fn add_extra_param(&mut self, key: String, value: String) {
        utils::add_extra_param(self, key, value);
    }

    pub fn get_request_params_as_vec(&self) -> Vec<(String, String)> {
        utils::get_request_params_as_vec(self)
    }

    pub fn get_headers(&self) -> Vec<(String, String)> {
        utils::get_headers()
    }
}
