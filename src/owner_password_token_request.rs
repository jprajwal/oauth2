use crate::utils;
use crate::OAuthParams;

#[derive(Debug)]
pub struct OwnerPasswordAccessTokenRequest {
    username: String,
    password: String,
    extras: Option<Vec<(String, String)>>,
    scope: Option<Vec<String>>,
}

impl OAuthParams for OwnerPasswordAccessTokenRequest {
    fn get_grant_type(&self) -> Option<String> {
        "password".to_owned().into()
    }

    fn get_username(&self) -> Option<String> {
        Some(self.username.clone())
    }

    fn get_password(&self) -> Option<String> {
        Some(self.password.clone())
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

impl OwnerPasswordAccessTokenRequest {
    pub fn new(username: String, password: String) -> Self {
        OwnerPasswordAccessTokenRequest {
            username,
            password,
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

#[cfg(test)]
mod owner_password_token_request_tests {
    use super::*;
    #[test]
    fn test_owner_password_token_request_params() {
        let mut request =
            OwnerPasswordAccessTokenRequest::new("test_user".into(), "test_password".into());
        request.add_scopes(["test_scope1".to_owned(), "test_scope2".to_owned()].into_iter());
        request.add_extra_param("extra1".into(), "extra1".into());

        let params = request.get_request_params_as_vec();
        println!("{params:?}");

        assert_eq!(
            params.contains(&("username".to_owned(), "test_user".to_owned())),
            true
        );
        assert_eq!(
            params.contains(&("password".to_owned(), "test_password".to_owned())),
            true
        );
        assert_eq!(
            params.contains(&("scope".to_owned(), "test_scope1 test_scope2".to_owned())),
            true
        );
        assert_eq!(
            params.contains(&("extra1".to_owned(), "extra1".to_owned())),
            true
        );
    }
}
