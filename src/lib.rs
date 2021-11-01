use std::{str::FromStr, time::SystemTime};

use http_cache_semantics::{AfterResponse, BeforeRequest, CachePolicy};
use http_types::{headers::HeaderValue, Method};
use surf::{
    middleware::{Middleware, Next},
    Client, Request, Response,
};

pub mod managers;

#[surf::utils::async_trait]
pub trait CacheManager {
    async fn get(
        &self,
        req: &Request,
    ) -> Result<Option<(Response, CachePolicy)>, http_types::Error>;
    async fn put(
        &self,
        req: &Request,
        res: &mut Response,
        policy: CachePolicy,
    ) -> Result<Response, http_types::Error>;
    async fn delete(&self, req: &Request) -> Result<(), http_types::Error>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum CacheMode {
    Default,
    NoStore,
    Reload,
    NoCache,
    ForceCache,
    OnlyIfCached,
}

/// Caches requests according to http spec
#[derive(Debug)]
pub struct Cache<T: CacheManager> {
    pub mode: CacheMode,
    pub cache_manager: T,
}

impl<T: CacheManager> Cache<T> {
    pub async fn run(
        &self,
        req: Request,
        client: Client,
        next: Next<'_>,
    ) -> Result<Response, http_types::Error> {
        let is_cacheable = (req.method() == Method::Get || req.method() == Method::Head)
            && self.mode != CacheMode::NoStore
            && self.mode != CacheMode::Reload;

        if !is_cacheable {
            return self.remote_fetch(req, client, next).await;
        }

        if let Some(store) = self.cache_manager.get(&req).await? {
            let (mut res, policy) = store;
            if let Some(warning_code) = get_warning_code(&res) {
                // https://tools.ietf.org/html/rfc7234#section-4.3.4
                //
                // If a stored response is selected for update, the cache MUST:
                //
                // * delete any Warning header fields in the stored response with
                //   warn-code 1xx (see Section 5.5);
                //
                // * retain any Warning header fields in the stored response with
                //   warn-code 2xx;
                //
                if warning_code >= 100 && warning_code < 200 {
                    res.remove_header("Warning");
                }
            }

            if self.mode == CacheMode::Default {
                Ok(self
                    .conditional_fetch(req, res, policy, client, next)
                    .await?)
            } else if self.mode == CacheMode::ForceCache || self.mode == CacheMode::OnlyIfCached {
                //   112 Disconnected operation
                // SHOULD be included if the cache is intentionally disconnected from
                // the rest of the network for a period of time.
                // (https://tools.ietf.org/html/rfc2616#section-14.46)
                add_warning(&mut res, req.url(), 112, "Disconnected operation");
                Ok(res)
            } else {
                Ok(self.remote_fetch(req, client, next).await?)
            }
        } else if self.mode == CacheMode::OnlyIfCached {
            // ENOTCACHED
            let err_res = http_types::Response::new(http_types::StatusCode::GatewayTimeout);
            Ok(err_res.into())
        } else {
            Ok(self.remote_fetch(req, client, next).await?)
        }
    }

    async fn conditional_fetch(
        &self,
        mut req: Request,
        mut cached_res: Response,
        mut policy: CachePolicy,
        client: Client,
        next: Next<'_>,
    ) -> Result<Response, http_types::Error> {
        let before_req = policy.before_request(&get_request_parts(&req), SystemTime::now());
        match before_req {
            BeforeRequest::Fresh(parts) => {
                update_response_headers(parts, &mut cached_res)?;
                return Ok(cached_res);
            }
            BeforeRequest::Stale {
                request: parts,
                matches,
            } => {
                if matches {
                    update_request_headers(parts, &mut req)?;
                }
            }
        }
        let copied_req = req.clone();
        match self.remote_fetch(req, client, next).await {
            Ok(cond_res) => {
                if cond_res.status().is_server_error() && must_revalidate(&cached_res) {
                    //   111 Revalidation failed
                    //   MUST be included if a cache returns a stale response
                    //   because an attempt to revalidate the response failed,
                    //   due to an inability to reach the server.
                    // (https://tools.ietf.org/html/rfc2616#section-14.46)
                    add_warning(
                        &mut cached_res,
                        copied_req.url(),
                        111,
                        "Revalidation failed",
                    );
                    Ok(cached_res)
                } else if cond_res.status() == http_types::StatusCode::NotModified {
                    let mut res = http_types::Response::new(cond_res.status());
                    for (key, value) in cond_res.iter() {
                        res.append_header(key, value.clone().as_str());
                    }
                    res.set_body(cached_res.body_string().await?);
                    let mut converted = Response::from(res);
                    let after_res = policy.after_response(
                        &get_request_parts(&copied_req),
                        &get_response_parts(&cond_res),
                        SystemTime::now(),
                    );
                    match after_res {
                        AfterResponse::Modified(new_policy, parts) => {
                            policy = new_policy;
                            update_response_headers(parts, &mut converted)?;
                        }
                        AfterResponse::NotModified(new_policy, parts) => {
                            policy = new_policy;
                            update_response_headers(parts, &mut converted)?;
                        }
                    }
                    let res = self
                        .cache_manager
                        .put(&copied_req, &mut converted, policy)
                        .await?;
                    Ok(res)
                } else {
                    Ok(cached_res)
                }
            }
            Err(e) => {
                if must_revalidate(&cached_res) {
                    Err(e)
                } else {
                    //   111 Revalidation failed
                    //   MUST be included if a cache returns a stale response
                    //   because an attempt to revalidate the response failed,
                    //   due to an inability to reach the server.
                    // (https://tools.ietf.org/html/rfc2616#section-14.46)
                    add_warning(
                        &mut cached_res,
                        copied_req.url(),
                        111,
                        "Revalidation failed",
                    );
                    //   199 Miscellaneous warning
                    //   The warning text MAY include arbitrary information to
                    //   be presented to a human user, or logged. A system
                    //   receiving this warning MUST NOT take any automated
                    //   action, besides presenting the warning to the user.
                    // (https://tools.ietf.org/html/rfc2616#section-14.46)
                    add_warning(
                        &mut cached_res,
                        copied_req.url(),
                        199,
                        format!("Miscellaneous Warning {}", e).as_str(),
                    );
                    Ok(cached_res)
                }
            }
        }
    }

    async fn remote_fetch(
        &self,
        req: Request,
        client: Client,
        next: Next<'_>,
    ) -> Result<Response, http_types::Error> {
        let copied_req = req.clone();
        let mut res = next.run(req, client).await?;
        let is_method_get_head =
            copied_req.method() == Method::Get || copied_req.method() == Method::Head;
        let policy = CachePolicy::new(&get_request_parts(&copied_req), &get_response_parts(&res));
        let is_cacheable = self.mode != CacheMode::NoStore
            && is_method_get_head
            && res.status() == http_types::StatusCode::Ok
            && policy.is_storable();
        if is_cacheable {
            Ok(self
                .cache_manager
                .put(&copied_req, &mut res, policy)
                .await?)
        } else if !is_method_get_head {
            self.cache_manager.delete(&copied_req).await?;
            Ok(res)
        } else {
            Ok(res)
        }
    }
}

fn must_revalidate(res: &Response) -> bool {
    if let Some(val) = res.header("Cache-Control") {
        val.as_str().to_lowercase().contains("must-revalidate")
    } else {
        false
    }
}

fn get_warning_code(res: &Response) -> Option<usize> {
    res.header("Warning").and_then(|hdr| {
        hdr.as_str()
            .chars()
            .take(3)
            .collect::<String>()
            .parse()
            .ok()
    })
}

fn update_request_headers(
    parts: http::request::Parts,
    req: &mut Request,
) -> Result<(), http_types::Error> {
    for header in parts.headers.iter() {
        req.set_header(
            header.0.as_str(),
            http_types::headers::HeaderValue::from_str(header.1.to_str()?)?,
        );
    }
    Ok(())
}

fn update_response_headers(
    parts: http::response::Parts,
    res: &mut Response,
) -> Result<(), http_types::Error> {
    for header in parts.headers.iter() {
        res.insert_header(
            header.0.as_str(),
            http_types::headers::HeaderValue::from_str(header.1.to_str()?)?,
        );
    }
    Ok(())
}

// Convert the surf::Response for CachePolicy to use
pub fn get_response_parts(res: &Response) -> http::response::Parts {
    let mut headers = http::HeaderMap::new();
    for header in res.iter() {
        headers.insert(
            http::header::HeaderName::from_str(header.0.as_str()).expect("Invalid header name"),
            http::HeaderValue::from_str(header.1.as_str()).expect("Invalid header value"),
        );
    }
    let status =
        http::StatusCode::from_str(res.status().to_string().as_ref()).expect("Invalid status code");
    let mut converted = http::response::Response::new(());
    converted.headers_mut().clone_from(&headers);
    converted.status_mut().clone_from(&status);
    let parts = converted.into_parts();
    parts.0
}

// Convert the surf::Request for CachePolicy to use
pub fn get_request_parts(req: &Request) -> http::request::Parts {
    let mut headers = http::HeaderMap::new();
    for header in req.iter() {
        headers.insert(
            http::header::HeaderName::from_str(header.0.as_str()).expect("Invalid header name"),
            http::HeaderValue::from_str(header.1.as_str()).expect("Invalid header value"),
        );
    }
    let uri = http::Uri::from_str(req.url().as_str()).expect("Invalid request uri");
    let method = http::Method::from_str(req.method().as_ref()).expect("Invalid request method");
    let mut converted = http::request::Request::new(());
    converted.headers_mut().clone_from(&headers);
    converted.uri_mut().clone_from(&uri);
    converted.method_mut().clone_from(&method);
    let parts = converted.into_parts();
    parts.0
}

fn add_warning(res: &mut Response, uri: &surf::http::Url, code: usize, message: &str) {
    //   Warning    = "Warning" ":" 1#warning-value
    // warning-value = warn-code SP warn-agent SP warn-text [SP warn-date]
    // warn-code  = 3DIGIT
    // warn-agent = ( host [ ":" port ] ) | pseudonym
    //                 ; the name or pseudonym of the server adding
    //                 ; the Warning header, for use in debugging
    // warn-text  = quoted-string
    // warn-date  = <"> HTTP-date <">
    // (https://tools.ietf.org/html/rfc2616#section-14.46)
    //
    let val = HeaderValue::from_str(
        format!(
            "{} {} {:?} \"{}\"",
            code,
            uri.host().expect("Invalid URL"),
            message,
            httpdate::fmt_http_date(SystemTime::now())
        )
        .as_str(),
    )
    .expect("Failed to generate warning string");
    res.append_header("Warning", val);
}

#[surf::utils::async_trait]
impl<T: CacheManager + 'static + Send + Sync> Middleware for Cache<T> {
    async fn handle(
        &self,
        req: Request,
        client: Client,
        next: Next<'_>,
    ) -> Result<Response, http_types::Error> {
        let res = self.run(req, client, next).await?;
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_types::{Response, StatusCode};
    use surf::Result;

    #[async_std::test]
    async fn can_get_warning_code() -> Result<()> {
        let url = surf::http::Url::from_str("https://example.com")?;
        let mut res = surf::Response::from(Response::new(StatusCode::Ok));
        add_warning(&mut res, &url, 111, "Revalidation failed");
        let code = get_warning_code(&res).unwrap();
        Ok(assert_eq!(code, 111))
    }

    #[async_std::test]
    async fn can_check_revalidate() {
        let mut res = Response::new(StatusCode::Ok);
        res.append_header("Cache-Control", "max-age=1733992, must-revalidate");
        let check = must_revalidate(&res.into());
        assert_eq!(check, true)
    }
}
