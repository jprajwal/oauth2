use crate::internal_traits;

#[derive(Default, Debug, PartialEq, Eq)]
pub struct AuthCodeRequest {
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
    pub fn new(client_id: String, response_type: String) -> Self {
        Self {
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
}

#[cfg(test)]
mod auth_code_request_tests {
    use super::AuthCodeRequest;
    use crate::OAuthRequestTrait;

    #[test]
    fn test_default() {
        let def = AuthCodeRequest::default();
        assert_eq!(
            def,
            AuthCodeRequest {
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
        let new = AuthCodeRequest::new("test_id".into(), "test_response_type".into());
        assert_eq!(
            new,
            AuthCodeRequest {
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
        let mut new = AuthCodeRequest::new("".into(), "".into());
        new.set_redirect_url("test_redirect_url".into());
        assert!(new.redirect_url == Some(String::from("test_redirect_url")));
    }

    #[test]
    fn test_google_auth_request_url() {
        let mut request = AuthCodeRequest::new(
            // "https://accounts.google.com/o/oauth2/v2/auth".into(),
            "test_id".into(),
            "code".into(),
        );
        request.add_scope("https://www.googleapis.com/auth/drive.metadata.readonly".into());
        request.add_scope("https://www.googleapis.com/auth/drive.metadata.writeonly".into());
        request.add_extra_param("access_type".into(), "offline".into());
        request.add_extra_param("include_granted_scopes".into(), "true".into());
        request.set_state("state_parameter_passthrough_value".into());
        request.set_redirect_url("https://oauth2.example.com/code".into());

        let params = request.get_request_params_as_vec();
        println!("{params:?}");

        assert!(params.contains(&("client_id".into(), "test_id".into())));
        assert!(params.contains(&("response_type".into(), "code".into())));
        assert!(params.contains(&(
            "redirect_uri".into(),
            "https://oauth2.example.com/code".into()
        )));
        assert!(params.contains(&("scope".into(), "https://www.googleapis.com/auth/drive.metadata.readonly https://www.googleapis.com/auth/drive.metadata.writeonly".into())));
        assert!(params.contains(&("state".into(), "state_parameter_passthrough_value".into())));
        assert!(params.contains(&("include_granted_scopes".into(), "true".into())));
        assert!(params.contains(&("access_type".into(), "offline".into())));
        assert_eq!(params.len(), 7);
    }
}
