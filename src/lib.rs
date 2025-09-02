//! Modern protection against cross-site request forgery (CSRF) attacks,
//!
//! This is _experimental_ middleware for [Tower](https://crates.io/crates/tower). It provides modern CSRF protection as outlined in a [blogpost](https://words.filippo.io/csrf/) by Filippo Valsorda, discussing the research background for integrating CSRF protection in Go 1.25's `net/http`.
//!
//! This boils down to (quoting from the blog):
//!
//! 1. Allow all GET, HEAD, or OPTIONS requests
//! 2. If the Origin header matches an allow-list of trusted origins, allow the request
//! 3. If the Sec-Fetch-Site header is present and the value is `same-origin` or `none`, allow the request, otherwise reject
//! 4. If neither the Sec-Fetch-Site nor the Origin headers are present, allow the request
//! 5. If the Origin header’s host (including the port) matches the Host header, allow the request, otherwise reject it
//!
//! The crate uses [tracing](https://docs.rs/tracing/latest/tracing/) to log passed requests and configuration changes. Errors are not logged, just pass through the
//! chain.
use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::result::Result;
use std::sync::Arc;
use std::task::{Context, Poll};

use http::{Method, Request, Response, Uri};
use tower::{BoxError, Layer, Service};
use tracing::{debug, instrument, trace};
use url::Url;

/// Errors that can occur during configuration of the layer.
#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    /// An invalid origin url was added as a trusted origin.
    #[error(transparent)]
    InvalidOriginUrl(#[from] url::ParseError),

    /// A origin url containing a path, query or fragment was added as a trusted origin.
    #[error("invalid origin {origin:?}: path, query, and fragment are not allowed")]
    InvalidOriginUrlComponents { origin: String },
}

/// Errors that can occur during request processing of the middleware.
///
/// These errors must be handled when using the middleware in web frameworks (such as axum) to e.g. log errors or
/// render appropriate responses.
#[derive(thiserror::Error, Debug, PartialEq)]
pub enum ProtectionError {
    /// A cross-origin request was detected.
    #[error("Cross-Origin request detected")]
    CrossOriginRequest,

    /// A cross-origin request was detected.
    #[error("Cross-Origin request from old browser detected")]
    CrossOriginRequestFromOldBrowser,

    /// The host request header cannot be parsed.
    #[error("Host header cannot be parsed")]
    MalformedHost(#[source] url::ParseError),

    /// The origin request header cannot be parsed.
    #[error("Origin header cannot be parsed")]
    MalformedOrigin(#[source] url::ParseError),
}

struct Bypass<T: Fn(&Method, &Uri) -> bool>(T);

impl<T: Fn(&Method, &Uri) -> bool> std::fmt::Debug for Bypass<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("<fn>").finish()
    }
}

trait Filter: std::fmt::Debug + Send + Sync {
    fn is_bypassed(&self, method: &Method, uri: &Uri) -> bool;
}

impl<T: Fn(&Method, &Uri) -> bool> Filter for Option<Bypass<T>>
where
    T: Send + Sync,
{
    fn is_bypassed(&self, method: &Method, uri: &Uri) -> bool {
        match self {
            Some(ref p) => p.0(method, uri),
            None => false,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct Origins(Arc<HashSet<String>>);

impl Origins {
    fn contains(&self, origin: &str) -> bool {
        self.0.contains(origin)
    }

    fn insert(&mut self, origin: impl Into<String>) {
        Arc::make_mut(&mut self.0).insert(origin.into());
    }
}

/// Decorates a HTTP service with CSRF protection.
#[derive(Clone, Debug)]
pub struct CrossOriginProtectionLayer {
    insecure_bypass: Arc<dyn Filter>,
    trusted_origins: Origins,
}

impl Default for CrossOriginProtectionLayer {
    fn default() -> Self {
        CrossOriginProtectionLayer {
            insecure_bypass: Arc::new(Option::<Bypass<fn(&Method, &Uri) -> bool>>::default()),
            trusted_origins: Origins::default(),
        }
    }
}

impl CrossOriginProtectionLayer {
    /// Adds a trusted origin which allows all requests with an `Origin` header which exactly matches
    /// the given value.
    ///
    /// Origin header values are of the form `scheme://host[:port]`.
    pub fn add_trusted_origin<S: Into<String>>(mut self, origin: S) -> Result<Self, ConfigError> {
        let origin = origin.into();

        // using url crate here for fragment support (see https://github.com/hyperium/http/issues/127)
        let url = Url::parse(&origin)?;

        // note that the url crate will always normalize an empty path to "/"
        if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
            return Err(ConfigError::InvalidOriginUrlComponents { origin });
        }

        debug!(origin = %origin, "added trusted origin");

        self.trusted_origins.insert(origin);

        Ok(self)
    }

    /// Adds a bypass function that returns `true` if the given request should bypass CSRF protection. Notes that this
    /// might be insecure.
    pub fn with_insecure_bypass<F>(self, predicate: F) -> CrossOriginProtectionLayer
    where
        F: Fn(&Method, &Uri) -> bool + Send + Sync + 'static,
    {
        debug!("added insecure bypass");

        CrossOriginProtectionLayer {
            insecure_bypass: Arc::new(Some(Bypass(predicate))),
            trusted_origins: self.trusted_origins,
        }
    }
}

impl<S> Layer<S> for CrossOriginProtectionLayer {
    type Service = CrossOriginProtectionMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CrossOriginProtectionMiddleware {
            inner,
            insecure_bypass: self.insecure_bypass.clone(),
            trusted_origins: self.trusted_origins.clone(),
        }
    }
}

/// CSRF protection middleware for HTTP requests.
#[derive(Clone, Debug)]
pub struct CrossOriginProtectionMiddleware<S> {
    inner: S,
    insecure_bypass: Arc<dyn Filter>,
    trusted_origins: Origins,
}

impl<S: Default> Default for CrossOriginProtectionMiddleware<S> {
    fn default() -> Self {
        Self {
            inner: S::default(),
            insecure_bypass: Arc::new(Option::<Bypass<fn(&Method, &Uri) -> bool>>::default()),
            trusted_origins: Origins::default(),
        }
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for CrossOriginProtectionMiddleware<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Error: Into<BoxError> + Send,
    S::Future: Future<Output = Result<Response<ResBody>, S::Error>> + Send,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    type Response = Response<ResBody>;

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        match self.verify(&req) {
            Ok(_) => Box::pin(async move { inner.call(req).await.map_err(Into::into) }),
            Err(err) => Box::pin(async move { Err(err.into()) }),
        }
    }

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }
}

impl<S> CrossOriginProtectionMiddleware<S> {
    #[instrument(skip(self, req), fields(uri = %req.uri()))]
    fn is_exempt<Body>(&self, req: &Request<Body>) -> bool {
        if self.insecure_bypass.is_bypassed(req.method(), req.uri()) {
            trace!("request passed: bypassed");
            return true;
        }

        if let Some(origin) = req.headers().get("origin") {
            if self
                .trusted_origins
                .contains(origin.to_str().unwrap_or_default())
            {
                trace!("request passed: trusted origin");
                return true;
            }
        }

        false
    }

    #[instrument(skip(self, req), fields(uri = %req.uri()))]
    fn verify<Body>(&self, req: &Request<Body>) -> Result<(), ProtectionError> {
        if matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
            trace!("request passed: safe method");
            return Ok(());
        }

        if let Some(sec_fetch_site) = req
            .headers()
            .get("sec-fetch-site")
            .and_then(|h| h.to_str().ok())
        {
            if matches!(sec_fetch_site, "same-origin" | "none") {
                trace!("request passed: sec-fetch-site is same-origin or none");
                return Ok(());
            } else if self.is_exempt(req) {
                return Ok(());
            } else {
                return Err(ProtectionError::CrossOriginRequest);
            }
        }

        match req.headers().get("origin").and_then(|h| h.to_str().ok()) {
            Some("null") => {}
            Some(origin) => {
                let origin = Url::parse(origin).map_err(ProtectionError::MalformedOrigin)?;

                let origin_host = origin.host_str();
                let host = req.headers().get("host").and_then(|h| h.to_str().ok());

                // the origin header matches the host header. note that the host header
                // doesn't include the scheme, so we don't know if this might be an
                // http→https cross-origin request. we fail open, since all modern
                // browsers support sec-fetch-site since 2023, and running an older
                // browser makes a clear security trade-off already. sites can mitigate
                // this with http strict transport security (hsts).

                match (origin_host, host) {
                    (Some(origin_host), Some(host)) if origin_host == host => {
                        trace!("request passed: origin is same as host - ");
                        return Ok(());
                    }
                    _ => {}
                }
            }
            None => {
                trace!("request passed: neither sec-fetch-site nor origin header (same-origin or not a browser request)");
                return Ok(());
            }
        }

        if self.is_exempt(req) {
            return Ok(());
        }

        Err(ProtectionError::CrossOriginRequestFromOldBrowser)
    }
}

#[cfg(test)]
mod tests {
    use tracing::Level;

    use super::*;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn init() {
        INIT.call_once(|| {
            tracing_subscriber::fmt()
                .with_max_level(Level::TRACE)
                .init();
        });
    }

    #[test]
    fn test_url_path_normalization() {
        for url in ["https://example.com/", "https://example.com"] {
            let url = Url::parse(url).unwrap();
            assert_eq!(url.path(), "/");
        }
    }

    #[test]
    fn test_layer_add_trusted_origin() {
        init();

        assert!(matches!(
            CrossOriginProtectionLayer::default().add_trusted_origin("https://example.com"),
            Ok(_)
        ));

        for origin in ["not a valid url", "example.com", "https://"] {
            assert!(matches!(
                CrossOriginProtectionLayer::default().add_trusted_origin(origin),
                Err(ConfigError::InvalidOriginUrl(_))
            ));
        }

        for origin in [
            "https://example.com/path",
            "https://example.com/path?query=value",
            "https://example.com/path#fragment",
        ] {
            assert!(matches!(
                CrossOriginProtectionLayer::default().add_trusted_origin(origin),
                Err(ConfigError::InvalidOriginUrlComponents { origin }) if origin == origin
            ));
        }
    }

    #[test]
    fn test_middleware_debug_trait() {
        init();

        let layer = CrossOriginProtectionLayer::default();

        let middleware = layer
            .clone()
            .with_insecure_bypass(|method, uri| method == Method::POST && uri.path() == "/bypass")
            .layer(());

        assert_eq!(
            format!("{:?}", middleware),
            "CrossOriginProtectionMiddleware { inner: (), insecure_bypass: Some(<fn>), trusted_origins: Origins({}) }"
        );

        let middleware = layer.layer(());

        assert_eq!(
            format!("{:?}", middleware),
            "CrossOriginProtectionMiddleware { inner: (), insecure_bypass: None, trusted_origins: Origins({}) }"
        );
    }

    #[test]
    fn test_middleware_sec_fetch_site() {
        init();

        let middleware: CrossOriginProtectionMiddleware<()> = Default::default();

        struct Test {
            name: &'static str,
            method: http::Method,
            sec_fetch_site: Option<&'static str>,
            origin: Option<&'static str>,
            result: Result<(), ProtectionError>,
        }

        let tests = [
            Test {
                name: "same-origin allowed",
                method: Method::GET,
                sec_fetch_site: Some("same-origin"),
                origin: None,
                result: Ok(()),
            },
            Test {
                name: "none allowed",
                method: Method::POST,
                sec_fetch_site: Some("none"),
                origin: None,
                result: Ok(()),
            },
            Test {
                name: "cross-site blocked",
                method: Method::POST,
                sec_fetch_site: Some("cross-site"),
                origin: None,
                result: Err(ProtectionError::CrossOriginRequest),
            },
            Test {
                name: "same-site blocked",
                method: Method::POST,
                sec_fetch_site: Some("same-site"),
                origin: None,
                result: Err(ProtectionError::CrossOriginRequest),
            },
            Test {
                name: "no header with no origin",
                method: Method::POST,
                sec_fetch_site: None,
                origin: None,
                result: Ok(()),
            },
            Test {
                name: "no header with matching origin",
                method: Method::POST,
                sec_fetch_site: None,
                origin: Some("https://example.com"),
                result: Ok(()),
            },
            Test {
                name: "no header with mismatched origin",
                method: Method::POST,
                sec_fetch_site: None,
                origin: Some("https://attacker.example"),
                result: Err(ProtectionError::CrossOriginRequestFromOldBrowser),
            },
            Test {
                name: "no header with null origin",
                method: Method::POST,
                sec_fetch_site: None,
                origin: Some("null"),
                result: Err(ProtectionError::CrossOriginRequestFromOldBrowser),
            },
            Test {
                name: "GET allowed",
                method: Method::GET,
                sec_fetch_site: Some("cross-site"),
                origin: None,
                result: Ok(()),
            },
            Test {
                name: "HEAD allowed",
                method: Method::HEAD,
                sec_fetch_site: Some("cross-site"),
                origin: None,
                result: Ok(()),
            },
            Test {
                name: "OPTIONS allowed",
                method: Method::OPTIONS,
                sec_fetch_site: Some("cross-site"),
                origin: None,
                result: Ok(()),
            },
            Test {
                name: "PUT allowed",
                method: Method::PUT,
                sec_fetch_site: Some("cross-site"),
                origin: None,
                result: Err(ProtectionError::CrossOriginRequest),
            },
        ];

        for test in tests {
            let mut req = Request::builder()
                .method(test.method)
                .header("host", "example.com");

            if let Some(sec_fetch_site) = test.sec_fetch_site {
                req = req.header("sec-fetch-site", sec_fetch_site);
            }

            if let Some(origin) = test.origin {
                req = req.header("origin", origin);
            }

            let req = req.body(()).unwrap();

            assert_eq!(middleware.verify(&req), test.result, "{}", test.name);
        }
    }

    #[test]
    fn test_middleware_trusted_origin_bypass() {
        init();

        let layer = CrossOriginProtectionLayer::default()
            .add_trusted_origin("https://trusted.example")
            .unwrap();

        let middleware = layer.layer(());

        struct Test {
            name: &'static str,
            sec_fetch_site: Option<&'static str>,
            origin: Option<&'static str>,
            result: Result<(), ProtectionError>,
        }

        let tests = [
            Test {
                name: "trusted origin without sec-fetch-site",
                origin: Some("https://trusted.example"),
                sec_fetch_site: None,
                result: Ok(()),
            },
            Test {
                name: "trusted origin with cross-site",
                origin: Some("https://trusted.example"),
                sec_fetch_site: Some("cross-site"),
                result: Ok(()),
            },
            Test {
                name: "untrusted origin without sec-fetch-site",
                origin: Some("https://attacker.example"),
                sec_fetch_site: None,
                result: Err(ProtectionError::CrossOriginRequestFromOldBrowser),
            },
            Test {
                name: "untrusted origin with cross-site",
                origin: Some("https://attacker.example"),
                sec_fetch_site: Some("cross-site"),
                result: Err(ProtectionError::CrossOriginRequest),
            },
        ];

        for test in tests {
            let mut req = Request::builder()
                .method("POST")
                .header("host", "example.com");

            if let Some(sec_fetch_site) = test.sec_fetch_site {
                req = req.header("sec-fetch-site", sec_fetch_site);
            }

            if let Some(origin) = test.origin {
                req = req.header("origin", origin);
            }

            let req = req.body(()).unwrap();

            assert_eq!(middleware.verify(&req), test.result, "{}", test.name);
        }
    }

    #[test]
    fn test_middleware_bypass() {
        init();

        let layer = CrossOriginProtectionLayer::default()
            .with_insecure_bypass(|_method, uri| -> bool { uri.path() == "/bypass" });

        let middleware = layer.layer(());

        struct Test {
            name: &'static str,
            path: &'static str,
            sec_fetch_site: Option<&'static str>,
            result: Result<(), ProtectionError>,
        }

        let tests = [
            Test {
                name: "bypass path without sec-fetch-site",
                path: "/bypass",
                sec_fetch_site: None,
                result: Ok(()),
            },
            Test {
                name: "bypass path with cross-site",
                path: "/bypass",
                sec_fetch_site: Some("cross-site"),
                result: Ok(()),
            },
            Test {
                name: "non-bypass path without sec-fetch-site",
                path: "/api",
                sec_fetch_site: None,
                result: Err(ProtectionError::CrossOriginRequestFromOldBrowser),
            },
            Test {
                name: "non-bypass path with cross-site",
                path: "/api",
                sec_fetch_site: Some("cross-site"),
                result: Err(ProtectionError::CrossOriginRequest),
            },
        ];

        for test in tests {
            let mut req = Request::builder()
                .method("POST")
                .header("host", "example.com")
                .header("origin", "https://attacker.example")
                .uri(format!("https://example.com{}", test.path));

            if let Some(sec_fetch_site) = test.sec_fetch_site {
                req = req.header("sec-fetch-site", sec_fetch_site);
            }

            let req = req.body(()).unwrap();

            assert_eq!(middleware.verify(&req), test.result, "{}", test.name);
        }
    }
}
