use crate::internal_traits;

#[derive(Default, Debug, PartialEq, Eq)]
pub struct AuthCodeRequest {
    auth_url: String,
    client_id: String,
    response_type: String,
    redirect_url: Option<String>,
    scope: Option<Vec<String>>,
    state: Option<String>,
    extras: Option<Vec<(String, String)>>,
}

impl internal_traits::OAuthParams for AuthCodeRequest {
    fn get_response_type(&self) -> Option<String> {
        Some(self.response_type.clone())
    }

    fn get_redirect_url(&self) -> Option<String> {
        self.redirect_url.clone()
    }

    fn get_client_id(&self) -> Option<String> {
        Some(self.client_id.clone())
    }

    fn get_scopes_mut(&mut self) -> Option<&mut Vec<String>> {
        self.scope.as_mut()
    }

    fn get_scopes_ref(&self) -> Option<&Vec<String>> {
        self.scope.as_ref()
    }

    fn get_state(&self) -> Option<String> {
        self.state.clone()
    }

    fn get_extra_params_mut(&mut self) -> Option<&mut Vec<(String, String)>> {
        self.extras.as_mut()
    }

    fn get_extra_params_ref(&self) -> Option<&Vec<(String, String)>> {
        self.extras.as_ref()
    }
}

impl AuthCodeRequest {
    pub fn new(auth_url: String, client_id: String, response_type: String) -> Self {
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

    pub fn set_redirect_url(&mut self, redirect_url: String) {
        self.redirect_url = Some(redirect_url);
    }

    pub fn set_state(&mut self, state: String) {
        self.state = Some(state);
    }

    pub fn extra_params(&mut self, k: String, v: String) {
        self.extras.get_or_insert(vec![]).push((k, v));
    }

    /*
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

    pub fn get_request_params_as_vec(&self) -> Vec<(String, String)> {
        let mut params = vec![
            ("client_id".into(), self.client_id.clone()),
            ("response_type".into(), self.response_type.clone()),
        ];
        if let Some(ref redirect_url) = self.redirect_url {
            params.push(("redirect_uri".into(), redirect_url.clone()));
        }
        if let Some(ref state) = self.state {
            params.push(("state".into(), state.clone()));
        }
        if let Some(ref scopes) = self.scope {
            let result = utils::join(scopes.iter().map(|s| s.as_str()), ' ');
            params.push(("scope".into(), result));
        }
        if let Some(ref extras) = self.extras {
            utils::append_to_vec(&mut params, extras.iter().map(|a| a.clone()));
        }
        params
    }
    */
}

#[cfg(test)]
mod tests {
    use super::AuthCodeRequest;
    use crate::OAuthRequestTrait;

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
        new.set_redirect_url("test_redirect_url".into());
        assert!(new.redirect_url == Some(String::from("test_redirect_url")));
    }

    #[test]
    fn test_google_auth_request_url() {
        let mut request = AuthCodeRequest::new(
            "https://accounts.google.com/o/oauth2/v2/auth".into(),
            "test_id".into(),
            "code".into(),
        );
        request.add_scope("https://www.googleapis.com/auth/drive.metadata.readonly".into());
        request.add_scope("https://www.googleapis.com/auth/drive.metadata.writeonly".into());
        request.extra_params("access_type".into(), "offline".into());
        request.extra_params("include_granted_scopes".into(), "true".into());
        request.set_state("state_parameter_passthrough_value".into());
        request.set_redirect_url("https://oauth2.example.com/code".into());
    }
}
