use crate::OAuthParams;

pub fn append_to_vec<T, I>(v: &mut Vec<T>, items: I)
where
    I: IntoIterator<Item = T>,
{
    items.into_iter().for_each(|item| {
        v.push(item);
    });
}

pub(crate) fn add_scope<R>(oauth_req: &mut R, scope: String)
where
    R: OAuthParams,
{
    match oauth_req.get_scopes_mut() {
        Some(v) => v.push(scope),
        None => {}
    }
}

pub(crate) fn add_scopes<R, I>(oauth_req: &mut R, scopes: I)
where
    R: OAuthParams,
    I: IntoIterator<Item = String>,
{
    match oauth_req.get_scopes_mut() {
        Some(v) => append_to_vec(v, scopes.into_iter()),
        None => {}
    }
}

pub(crate) fn get_request_params_as_vec<R>(oauth_req: &R) -> Vec<(String, String)>
where
    R: OAuthParams,
{
    let mut params = vec![];
    match oauth_req.get_grant_type() {
        Some(s) => params.push((String::from("grant_type"), s)),
        None => {}
    }
    match oauth_req.get_response_type() {
        Some(s) => params.push((String::from("response_type"), s)),
        None => {}
    }
    match oauth_req.get_redirect_url() {
        Some(s) => params.push((String::from("redirect_uri"), s)),
        None => {}
    }
    match oauth_req.get_client_id() {
        Some(s) => params.push((String::from("client_id"), s)),
        None => {}
    }
    match oauth_req.get_client_secret() {
        Some(s) => params.push((String::from("client_secret"), s)),
        None => {}
    }
    match oauth_req.get_scopes_ref() {
        Some(v) if v.len() > 0 => {
            params.push((String::from("scope"), v.join(" ")));
        }
        _ => {}
    }
    match oauth_req.get_state() {
        Some(s) => params.push((String::from("state"), s)),
        None => {}
    }
    match oauth_req.get_extra_params_ref() {
        Some(v) if v.len() > 0 => {
            append_to_vec(&mut params, v.iter().map(|a| a.clone()));
        }
        _ => {}
    }
    match oauth_req.get_username() {
        Some(s) => params.push((String::from("username"), s)),
        None => {}
    }
    match oauth_req.get_password() {
        Some(s) => params.push((String::from("password"), s)),
        None => {}
    }
    match oauth_req.get_code() {
        Some(s) => params.push((String::from("code"), s)),
        None => {}
    }
    match oauth_req.get_refresh_token() {
        Some(s) => params.push((String::from("refresh_token"), s)),
        None => {}
    }
    return params;
}

pub(crate) fn add_extra_param<R>(oauth_req: &mut R, key: String, val: String)
where
    R: OAuthParams,
{
    match oauth_req.get_extra_params_mut() {
        Some(v) => v.push((key, val)),
        None => {}
    }
}

pub(crate) fn get_headers() -> Vec<(String, String)> {
    return vec![(
        "Content-Type".into(),
        "application/x-www-form-urlencoded".into(),
    )];
}
