use crate::utils;

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
}

pub trait OAuthRequestTrait {
    fn add_scope(&mut self, scope: String);
    fn add_scopes<I>(&mut self, scopes: I)
    where
        I: IntoIterator<Item = String>;
    fn get_request_params_as_vec(&self) -> Vec<(String, String)>;
}

impl<T> OAuthRequestTrait for T
where
    T: OAuthParams,
{
    fn add_scope(&mut self, scope: String) {
        match self.get_scopes_mut() {
            Some(v) => v.push(scope),
            None => {}
        }
    }

    fn add_scopes<I>(&mut self, scopes: I)
    where
        I: IntoIterator<Item = String>,
    {
        match self.get_scopes_mut() {
            Some(v) => utils::append_to_vec(v, scopes.into_iter()),
            None => {}
        }
    }

    fn get_request_params_as_vec(&self) -> Vec<(String, String)> {
        let mut params = vec![];
        match self.get_grant_type() {
            Some(s) => params.push((String::from("grant_type"), s)),
            None => {}
        }
        match self.get_response_type() {
            Some(s) => params.push((String::from("response_type"), s)),
            None => {}
        }
        match self.get_redirect_url() {
            Some(s) => params.push((String::from("redirect_uri"), s)),
            None => {}
        }
        match self.get_client_id() {
            Some(s) => params.push((String::from("client_id"), s)),
            None => {}
        }
        match self.get_client_secret() {
            Some(s) => params.push((String::from("client_secret"), s)),
            None => {}
        }
        match self.get_scopes_ref() {
            Some(v) => {
                params.push((String::from("scopes"), v.join(" ")));
            }
            None => {}
        }
        match self.get_state() {
            Some(s) => params.push((String::from("state"), s)),
            None => {}
        }
        match self.get_extra_params_ref() {
            Some(v) => {
                utils::append_to_vec(&mut params, v.iter().map(|a| a.clone()));
            }
            None => {}
        }
        return params;
    }
}
