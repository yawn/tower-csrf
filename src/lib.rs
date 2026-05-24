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
#[derive(Clone, Debug, thiserror::Error, PartialEq)]
pub enum ConfigError {
    /// An invalid origin url was added as a trusted origin.
    #[error(transparent)]
    InvalidOriginUrl(#[from] url::ParseError),

    /// A origin url containing a path, query or fragment was added as a trusted origin.
    #[error("invalid origin {origin:?}: path, query, and fragment are not allowed")]
    InvalidOriginUrlComponents { origin: String },

    /// An opaque-origin url (e.g. `file://`, `data:`) was added as a trusted origin.
    /// Such origins serialize to `"null"` and can never match a request Origin.
    #[error("invalid origin {origin:?}: opaque origins cannot serve as trusted origins")]
    OpaqueOrigin { origin: String },
}

/// Errors that can occur during request processing of the middleware.
///
/// These errors must be handled when using the middleware in web frameworks (such as axum) to e.g. log errors or
/// render appropriate responses.
#[derive(Clone, Debug, thiserror::Error, PartialEq)]
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

        if !url.origin().is_tuple() {
            return Err(ConfigError::OpaqueOrigin { origin });
        }

        // Store the canonical ascii serialization (lowercased scheme/host,
        // default ports stripped) so the lookup against parsed request
        // origins matches regardless of how the developer typed the config.
        let normalized = url.origin().ascii_serialization();

        debug!(origin = %normalized, "added trusted origin");

        self.trusted_origins.insert(normalized);

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
        // see https://docs.rs/tower/latest/tower/trait.Service.html#be-careful-when-cloning-inner-services
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

        let trusted = req
            .headers()
            .get("origin")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| Url::parse(s).ok())
            .map(|u| u.origin().ascii_serialization())
            .is_some_and(|s| self.trusted_origins.contains(&s));

        if trusted {
            trace!("request passed: trusted origin");
            return true;
        }

        false
    }

    #[instrument(skip(self, req), fields(uri = %req.uri()))]
    fn verify<Body>(&self, req: &Request<Body>) -> Result<(), ProtectionError> {
        if matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
            trace!("request passed: safe method");
            return Ok(());
        }

        // Raw bytes for Go parity: empty collapses to absent, non-decodable hits the default arm.
        match req.headers().get("sec-fetch-site").map(|h| h.as_bytes()) {
            Some(b"same-origin") | Some(b"none") => {
                trace!("request passed: sec-fetch-site is same-origin or none");
                return Ok(());
            }
            None | Some(b"") => {} // fall through to Origin check
            Some(_) if self.is_exempt(req) => return Ok(()),
            Some(_) => return Err(ProtectionError::CrossOriginRequest),
        }

        // Same: empty is absent; any decode/parse failure falls through to is_exempt.
        match req.headers().get("origin").map(|h| h.as_bytes()) {
            None | Some(b"") => {
                trace!("request passed: neither sec-fetch-site nor origin header (same-origin or not a browser request)");
                return Ok(());
            }
            Some(bytes) => {
                let parsed = std::str::from_utf8(bytes)
                    .ok()
                    .and_then(|s| Url::parse(s).ok());

                if let Some(origin_url) = parsed {
                    // Compare effective ports (scheme default when implicit). Host has no
                    // scheme, so http→https can't be detected here; fail open per HSTS.
                    let authority = req
                        .headers()
                        .get("host")
                        .and_then(|h| h.to_str().ok())
                        .and_then(|h| h.parse::<http::uri::Authority>().ok());

                    if let (Some(origin_host), Some(authority)) =
                        (origin_url.host_str(), authority)
                    {
                        let origin_port = origin_url.port_or_known_default();
                        let host_port = authority.port_u16().or(origin_port);

                        if origin_host == authority.host() && origin_port == host_port {
                            trace!("request passed: origin is same as host");
                            return Ok(());
                        }
                    }
                }
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
    use std::sync::Once;

    use tracing::Level;

    use super::*;

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

        // Opaque-origin inputs serialize to "null" and can never match an
        // incoming request Origin; reject them at config time rather than
        // silently storing a dead entry.
        assert!(matches!(
            CrossOriginProtectionLayer::default().add_trusted_origin("file:///"),
            Err(ConfigError::OpaqueOrigin { .. })
        ));
    }

    #[test]
    fn test_middleware_trusted_origin_normalization() {
        init();

        // Each row inserts a non-canonical form of the trusted origin and
        // sends a request bearing the canonical browser-style Origin header.
        // Pre-M2 these would all silently fail to match because the raw
        // input string was stored byte-for-byte.
        struct Test {
            name: &'static str,
            trusted: &'static str,
            origin: &'static str,
        }

        let tests = [
            Test {
                name: "scheme and host case folded",
                trusted: "HTTPS://Example.COM",
                origin: "https://example.com",
            },
            Test {
                name: "trailing slash stripped",
                trusted: "https://example.com/",
                origin: "https://example.com",
            },
            Test {
                name: "default https port stripped",
                trusted: "https://example.com:443",
                origin: "https://example.com",
            },
            Test {
                name: "default http port stripped",
                trusted: "http://example.com:80",
                origin: "http://example.com",
            },
            Test {
                name: "non-default port preserved",
                trusted: "https://example.com:8443",
                origin: "https://example.com:8443",
            },
        ];

        for test in tests {
            let middleware = CrossOriginProtectionLayer::default()
                .add_trusted_origin(test.trusted)
                .unwrap_or_else(|e| panic!("{}: add_trusted_origin failed: {e}", test.name))
                .layer(());

            let req = Request::builder()
                .method("POST")
                .header("host", "other.example")
                .header("origin", test.origin)
                .header("sec-fetch-site", "cross-site")
                .body(())
                .unwrap();

            assert_eq!(middleware.verify(&req), Ok(()), "{}", test.name);
        }
    }

    #[test]
    fn test_middleware_origin_host_port_match() {
        init();

        let middleware: CrossOriginProtectionMiddleware<()> = Default::default();

        struct Test {
            name: &'static str,
            host: &'static str,
            origin: &'static str,
            result: Result<(), ProtectionError>,
        }

        let tests = [
            Test {
                name: "default port both sides",
                host: "example.com",
                origin: "https://example.com",
                result: Ok(()),
            },
            Test {
                name: "same non-default port both sides",
                host: "example.com:8443",
                origin: "https://example.com:8443",
                result: Ok(()),
            },
            Test {
                name: "explicit default port both sides",
                host: "example.com:443",
                origin: "https://example.com:443",
                result: Ok(()),
            },
            Test {
                name: "mismatched non-default ports",
                host: "example.com:8443",
                origin: "https://example.com:8444",
                result: Err(ProtectionError::CrossOriginRequestFromOldBrowser),
            },
            Test {
                name: "origin has explicit default, host implicit",
                host: "example.com",
                origin: "https://example.com:443",
                result: Ok(()),
            },
            Test {
                name: "host has explicit default, origin implicit",
                host: "example.com:443",
                origin: "https://example.com",
                result: Ok(()),
            },
            Test {
                name: "unparseable host",
                host: "not a valid authority",
                origin: "https://example.com",
                result: Err(ProtectionError::CrossOriginRequestFromOldBrowser),
            },
        ];

        for test in tests {
            let req = Request::builder()
                .method(Method::POST)
                .header("host", test.host)
                .header("origin", test.origin)
                .body(())
                .unwrap();

            assert_eq!(middleware.verify(&req), test.result, "{}", test.name);
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

        const NON_DECODABLE: &[u8] = &[0xFF, 0xFE];
        assert!(
            http::HeaderValue::from_bytes(NON_DECODABLE)
                .expect("NON_DECODABLE must be a valid HeaderValue")
                .to_str()
                .is_err(),
            "NON_DECODABLE must fail HeaderValue::to_str()"
        );

        struct Test {
            name: &'static str,
            method: http::Method,
            sec_fetch_site: Option<&'static [u8]>,
            origin: Option<&'static [u8]>,
            result: Result<(), ProtectionError>,
        }

        let tests = [
            Test {
                name: "same-origin allowed",
                method: Method::GET,
                sec_fetch_site: Some(b"same-origin"),
                origin: None,
                result: Ok(()),
            },
            Test {
                name: "none allowed",
                method: Method::POST,
                sec_fetch_site: Some(b"none"),
                origin: None,
                result: Ok(()),
            },
            Test {
                name: "cross-site blocked",
                method: Method::POST,
                sec_fetch_site: Some(b"cross-site"),
                origin: None,
                result: Err(ProtectionError::CrossOriginRequest),
            },
            Test {
                name: "same-site blocked",
                method: Method::POST,
                sec_fetch_site: Some(b"same-site"),
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
                origin: Some(b"https://example.com"),
                result: Ok(()),
            },
            Test {
                name: "no header with mismatched origin",
                method: Method::POST,
                sec_fetch_site: None,
                origin: Some(b"https://attacker.example"),
                result: Err(ProtectionError::CrossOriginRequestFromOldBrowser),
            },
            Test {
                name: "no header with null origin",
                method: Method::POST,
                sec_fetch_site: None,
                origin: Some(b"null"),
                result: Err(ProtectionError::CrossOriginRequestFromOldBrowser),
            },
            Test {
                name: "GET allowed",
                method: Method::GET,
                sec_fetch_site: Some(b"cross-site"),
                origin: None,
                result: Ok(()),
            },
            Test {
                name: "HEAD allowed",
                method: Method::HEAD,
                sec_fetch_site: Some(b"cross-site"),
                origin: None,
                result: Ok(()),
            },
            Test {
                name: "OPTIONS allowed",
                method: Method::OPTIONS,
                sec_fetch_site: Some(b"cross-site"),
                origin: None,
                result: Ok(()),
            },
            Test {
                name: "PUT allowed",
                method: Method::PUT,
                sec_fetch_site: Some(b"cross-site"),
                origin: None,
                result: Err(ProtectionError::CrossOriginRequest),
            },
            Test {
                name: "non-decodable origin without sec-fetch-site rejected",
                method: Method::POST,
                sec_fetch_site: None,
                origin: Some(NON_DECODABLE),
                result: Err(ProtectionError::CrossOriginRequestFromOldBrowser),
            },
            Test {
                name: "non-decodable sec-fetch-site without origin rejected",
                method: Method::POST,
                sec_fetch_site: Some(NON_DECODABLE),
                origin: None,
                result: Err(ProtectionError::CrossOriginRequest),
            },
            Test {
                name: "empty sec-fetch-site without origin allowed",
                method: Method::POST,
                sec_fetch_site: Some(b""),
                origin: None,
                result: Ok(()),
            },
            Test {
                name: "empty origin without sec-fetch-site allowed",
                method: Method::POST,
                sec_fetch_site: None,
                origin: Some(b""),
                result: Ok(()),
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
