pub trait OAuthParams {
    fn get_grant_type(&self) -> Option<String> {
        None
    }

    fn get_response_type(&self) -> Option<String> {
        None
    }

    fn get_redirect_url(&self) -> Option<String> {
        None
    }

    fn get_client_id(&self) -> Option<String> {
        None
    }

    fn get_client_secret(&self) -> Option<String> {
        None
    }

    fn get_scopes_mut(&mut self) -> Option<&mut Vec<String>> {
        None
    }

    fn get_scopes_ref(&self) -> Option<&Vec<String>> {
        None
    }

    fn get_state(&self) -> Option<String> {
        None
    }

    fn get_extra_params_mut(&mut self) -> Option<&mut Vec<(String, String)>> {
        None
    }

    fn get_extra_params_ref(&self) -> Option<&Vec<(String, String)>> {
        None
    }

    fn get_username(&self) -> Option<String> {
        None
    }

    fn get_password(&self) -> Option<String> {
        None
    }

    fn get_code(&self) -> Option<String> {
        None
    }

    fn get_refresh_token(&self) -> Option<String> {
        None
    }
}
