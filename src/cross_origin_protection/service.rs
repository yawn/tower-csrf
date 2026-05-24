use std::fmt::{self, Debug, Formatter};
use std::str;
use std::sync::Arc;
use std::task::{Context, Poll};

use http::{Method, Request, Response, Uri};
use tower::Service;

use super::future::ResponseFuture;
use super::url::UriExt;
use super::{BypassFn, DebugFn, Origins, ProtectionError};

/// CSRF protection middleware for HTTP requests.
#[derive(Clone)]
pub struct CrossOriginProtectionMiddleware<S> {
    inner: S,
    insecure_bypass: Option<Arc<BypassFn>>,
    trusted_origins: Origins,
}

impl<S> CrossOriginProtectionMiddleware<S> {
    pub(super) fn new(
        inner: S,
        insecure_bypass: Option<Arc<BypassFn>>,
        trusted_origins: Origins,
    ) -> Self {
        Self {
            inner,
            insecure_bypass,
            trusted_origins,
        }
    }

    fn is_exempt(&self, method: &Method, uri: &Uri, origin: Option<&Uri>) -> bool {
        if self
            .insecure_bypass
            .as_ref()
            .map_or(false, |p| p(method, uri))
        {
            #[cfg(feature = "tracing")]
            tracing::trace!(uri = %uri, "request passed: bypassed");
            return true;
        }

        let trusted = origin
            .and_then(|u| u.canonical())
            .map_or(false, |s| self.trusted_origins.contains(&s));

        if trusted {
            #[cfg(feature = "tracing")]
            tracing::trace!(uri = %uri, "request passed: trusted origin");
            return true;
        }

        false
    }

    pub(super) fn verify<Body>(&self, req: &Request<Body>) -> Result<(), ProtectionError> {
        if matches!(
            req.method(),
            &Method::GET | &Method::HEAD | &Method::OPTIONS
        ) {
            #[cfg(feature = "tracing")]
            tracing::trace!(uri = %req.uri(), "request passed: safe method");
            return Ok(());
        }

        let origin = req.headers().get("origin").map(|h| h.as_bytes());

        let origin_uri = origin
            .filter(|b| !b.is_empty())
            .and_then(|b| str::from_utf8(b).ok())
            .and_then(|s| s.parse::<Uri>().ok());

        let sec_fetch_site = req.headers().get("sec-fetch-site").map(|h| h.as_bytes());

        // Fetch spec mandates lowercase here; exact byte match is intentional.
        match sec_fetch_site {
            Some(b"same-origin") | Some(b"none") => {
                #[cfg(feature = "tracing")]
                tracing::trace!(uri = %req.uri(), "request passed: sec-fetch-site is same-origin or none");
                return Ok(());
            }
            None | Some(b"") => {} // fall through to Origin check
            Some(_) if self.is_exempt(req.method(), req.uri(), origin_uri.as_ref()) => {
                return Ok(())
            }
            Some(_) => return Err(ProtectionError::CrossOriginRequest),
        }

        if matches!(origin, None | Some(b"")) {
            #[cfg(feature = "tracing")]
            tracing::trace!(uri = %req.uri(), "request passed: neither sec-fetch-site nor origin header (same-origin or not a browser request)");
            return Ok(());
        }

        let host = req.headers().get("host").map(|h| h.as_bytes());

        if let Some(uri) = &origin_uri {
            // compare effective ports (scheme default when implicit). Host has no scheme, so http→https can't be detected here; fail open per HSTS.
            let authority = host
                .and_then(|b| str::from_utf8(b).ok())
                .and_then(|s| s.parse::<http::uri::Authority>().ok());

            // fall back to the request URI when the Host header is missing or unparseable
            let (host_name, port_host) = match authority.as_ref() {
                Some(a) => (Some(a.host()), a.port_u16()),
                None => (req.uri().host(), req.uri().port_u16()),
            };

            if let (Some(origin_host), Some(host_name)) = (uri.host(), host_name) {
                let port_origin = uri.effective_port();
                let port_host = port_host.or(port_origin);

                if origin_host.eq_ignore_ascii_case(host_name) && port_origin == port_host {
                    #[cfg(feature = "tracing")]
                    tracing::trace!(uri = %req.uri(), "request passed: origin is same as host");
                    return Ok(());
                }
            }
        }

        if self.is_exempt(req.method(), req.uri(), origin_uri.as_ref()) {
            return Ok(());
        }

        Err(ProtectionError::CrossOriginRequestFromOldBrowser)
    }
}

impl<S: Default> Default for CrossOriginProtectionMiddleware<S> {
    fn default() -> Self {
        Self {
            inner: S::default(),
            insecure_bypass: None,
            trusted_origins: Origins::default(),
        }
    }
}

impl<S: Debug> Debug for CrossOriginProtectionMiddleware<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CrossOriginProtectionMiddleware")
            .field("inner", &self.inner)
            .field(
                "insecure_bypass",
                &self.insecure_bypass.as_ref().map(|_| DebugFn),
            )
            .field("trusted_origins", &self.trusted_origins)
            .finish()
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for CrossOriginProtectionMiddleware<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ResBody: Default,
{
    type Error = S::Error;
    type Future = ResponseFuture<S::Future, ResBody>;
    type Response = Response<ResBody>;

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        match self.verify(&req) {
            Ok(_) => ResponseFuture::future(self.inner.call(req)),
            Err(err) => ResponseFuture::rejected(err),
        }
    }

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }
}
