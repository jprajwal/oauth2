use crate::utils;
use crate::OAuthParams;

#[derive(Debug)]
pub struct AuthCodeAccessTokenRequest {
    code: String,
    redirect_url: String,
    client_id: String,
    client_secret: Option<String>,
    scope: Option<Vec<String>>,
    extras: Option<Vec<(String, String)>>,
}

impl OAuthParams for AuthCodeAccessTokenRequest {
    fn get_grant_type(&self) -> Option<String> {
        "authorization_code".to_owned().into()
    }

    fn get_code(&self) -> Option<String> {
        self.code.clone().into()
    }

    fn get_redirect_url(&self) -> Option<String> {
        self.redirect_url.clone().into()
    }

    fn get_client_id(&self) -> Option<String> {
        self.client_id.clone().into()
    }

    fn get_client_secret(&self) -> Option<String> {
        self.client_secret.clone()
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

    pub fn set_client_secret(&mut self, secret: String) {
        self.client_secret = Some(secret);
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
}
