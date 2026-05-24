use std::collections::HashSet;
use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use http::{Method, Uri};

mod future;
mod layer;
mod service;
mod url;

pub use future::ResponseFuture;
pub use layer::CrossOriginProtectionLayer;
pub use service::CrossOriginProtectionMiddleware;

/// Errors that can occur during configuration of the layer.
#[derive(Clone, Debug, thiserror::Error, PartialEq)]
pub enum ConfigError {
    /// The origin string could not be parsed as a URI.
    #[error("invalid origin {origin:?}: {message}")]
    InvalidOriginUrl { origin: String, message: String },

    /// A origin url containing a path, query or fragment was added as a trusted origin.
    #[error("invalid origin {origin:?}: path, query, and fragment are not allowed")]
    InvalidOriginUrlComponents { origin: String },

    /// An origin with a scheme other than `http` or `https` (e.g. `file://`,
    /// `mailto:`, or a bare host with no scheme) was added as a trusted
    /// origin. Such origins can never match a browser-supplied request Origin.
    #[error("invalid origin {origin:?}: scheme must be http or https")]
    OpaqueOrigin { origin: String },

    /// A trusted origin contained non-ASCII characters. Browsers send IDN
    /// hostnames in punycode form, so the configured value must use the
    /// punycode form (e.g. `xn--exmple-cua.com`) to ever match.
    #[error("invalid origin {origin:?}: non-ASCII hostnames must be supplied in punycode (xn--…)")]
    NonAsciiHostname { origin: String },
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
}

type BypassFn = dyn Fn(&Method, &Uri) -> bool + Send + Sync + 'static;

struct DebugFn;

impl Debug for DebugFn {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("<fn>")
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

#[cfg(test)]
mod tests {
    use std::sync::Once;

    use http::Request;
    use tower::Layer;

    use super::*;

    static INIT: Once = Once::new();

    fn init() {
        INIT.call_once(|| {
            #[cfg(feature = "tracing")]
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .init();
        });
    }

    #[test]
    fn test_layer_add_trusted_origin() {
        init();

        // Smoke check that the layer threads parse_origin's Ok and Err
        // through; the full validation matrix lives in url.rs.
        assert!(CrossOriginProtectionLayer::default()
            .add_trusted_origin("https://example.com")
            .is_ok());
        assert!(matches!(
            CrossOriginProtectionLayer::default().add_trusted_origin("not a valid url"),
            Err(ConfigError::InvalidOriginUrl { .. })
        ));
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

    #[test]
    fn test_middleware_bypass_applies_when_origin_unparseable() {
        init();

        let middleware = CrossOriginProtectionLayer::default()
            .with_insecure_bypass(|_method, uri| uri.path() == "/bypass")
            .layer(());

        let req = Request::builder()
            .method("POST")
            .uri("https://example.com/bypass")
            .header("host", "example.com")
            .header(
                "origin",
                http::HeaderValue::from_bytes(&[0xFF, 0xFE]).unwrap(),
            )
            .body(())
            .unwrap();

        assert_eq!(middleware.verify(&req), Ok(()));
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
    fn test_middleware_origin_host_port_match() {
        init();

        let middleware: CrossOriginProtectionMiddleware<()> = Default::default();

        struct Test {
            name: &'static str,
            uri: &'static str,
            host: Option<&'static str>,
            origin: &'static str,
            result: Result<(), ProtectionError>,
        }

        let tests = [
            Test {
                name: "default port both sides",
                uri: "/",
                host: Some("example.com"),
                origin: "https://example.com",
                result: Ok(()),
            },
            Test {
                name: "same non-default port both sides",
                uri: "/",
                host: Some("example.com:8443"),
                origin: "https://example.com:8443",
                result: Ok(()),
            },
            Test {
                name: "explicit default port both sides",
                uri: "/",
                host: Some("example.com:443"),
                origin: "https://example.com:443",
                result: Ok(()),
            },
            Test {
                name: "mismatched non-default ports",
                uri: "/",
                host: Some("example.com:8443"),
                origin: "https://example.com:8444",
                result: Err(ProtectionError::CrossOriginRequestFromOldBrowser),
            },
            Test {
                name: "origin has explicit default, host implicit",
                uri: "/",
                host: Some("example.com"),
                origin: "https://example.com:443",
                result: Ok(()),
            },
            Test {
                name: "host has explicit default, origin implicit",
                uri: "/",
                host: Some("example.com:443"),
                origin: "https://example.com",
                result: Ok(()),
            },
            Test {
                name: "unparseable host falls back to uri authority",
                uri: "https://example.com/path",
                host: Some("not a valid authority"),
                origin: "https://example.com",
                result: Ok(()),
            },
            Test {
                name: "missing host, uri carries authority (match)",
                uri: "https://example.com/path",
                host: None,
                origin: "https://example.com",
                result: Ok(()),
            },
            Test {
                name: "missing host, uri authority mismatch",
                uri: "https://other.example/path",
                host: None,
                origin: "https://example.com",
                result: Err(ProtectionError::CrossOriginRequestFromOldBrowser),
            },
            Test {
                name: "missing host and no uri authority",
                uri: "/path",
                host: None,
                origin: "https://example.com",
                result: Err(ProtectionError::CrossOriginRequestFromOldBrowser),
            },
        ];

        for test in tests {
            let mut req = Request::builder().method(Method::POST).uri(test.uri);

            if let Some(host) = test.host {
                req = req.header("host", host);
            }

            let req = req.header("origin", test.origin).body(()).unwrap();

            assert_eq!(middleware.verify(&req), test.result, "{}", test.name);
        }
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
                name: "PUT blocked",
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
}
