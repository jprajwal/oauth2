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

    /*
    pub fn req_body(&self) -> Result<String, Box<dyn Error>> {
        let mut params = vec![("grant_type", "password")];
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

    pub fn get_token<T, H>(
        &self,
        http: H,
        auth_header: Vec<(String, String)>,
    ) -> Result<T, Box<dyn Error>>
    where
        T: Token + DeserializeOwned,
        H: HttpAdapter,
    {
        let url = self.token_url().map_err(|e| e.to_string())?;
        let form_data = self.req_body().map_err(|e| e.to_string())?;
        let mut headers = self.get_headers();
        headers.extend(auth_header);
        let (status_code, response) = http
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
                    serde_json::from_str(response.as_str()).map_err(|_| response.clone())?;
                return Err(Box::new(error));
            }
        }
    }
    */
}
