use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::result::Result;
use std::sync::Arc;
use std::task::{Context, Poll};

use http::{Method, Request, Response, Uri};
use tower::{BoxError, Layer, Service};
use url::Url;

#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    #[error(transparent)]
    InvalidOriginUrl(#[from] url::ParseError),

    #[error("invalid origin {origin:?}: path, query, and fragment are not allowed")]
    InvalidOriginUrlComponents { origin: String },
}

#[derive(thiserror::Error, Debug)]
pub enum ProtectionError {
    #[error("Cross-Origin request detected")]
    CrossOriginRequest,

    #[error("Host header cannot be parsed")]
    MalformedHost(#[source] url::ParseError),

    #[error("Origin header cannot be parsed")]
    MalformedOrigin(#[source] url::ParseError),

    #[error("Sec-Fetch-Site header is present with an unexpected value")]
    SecFetchSiteUnexpectedValue(String),
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
    pub fn add_trusted_origin<S: Into<String>>(mut self, origin: S) -> Result<Self, ConfigError> {
        let origin = origin.into();

        // using url crate here for fragment support (see https://github.com/hyperium/http/issues/127)
        let url = Url::parse(&origin)?;

        if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
            return Err(ConfigError::InvalidOriginUrlComponents { origin });
        }

        self.trusted_origins.insert(origin);

        Ok(self)
    }

    pub fn with_insecure_bypass<F>(self, predicate: F) -> CrossOriginProtectionLayer
    where
        F: Fn(&Method, &Uri) -> bool + Send + Sync + 'static,
    {
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
    fn verify<Body>(&self, req: &Request<Body>) -> Result<(), ProtectionError> {
        if self.insecure_bypass.is_bypassed(req.method(), req.uri()) {
            return Ok(());
        }

        if matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
            return Ok(());
        }

        let origin = req.headers().get("origin");
        let mut origin_url = None;

        if let Some(origin) = origin.and_then(|h| h.to_str().ok()) {
            if self.trusted_origins.contains(origin) {
                return Ok(());
            }

            if origin != "null" {
                let origin = Url::parse(origin).map_err(ProtectionError::MalformedOrigin)?;
                origin_url = Some(origin);
            }
        }

        let sec_fetch_site = req.headers().get("sec-fetch-site");

        if let Some(sec_fetch_site) = sec_fetch_site.and_then(|h| h.to_str().ok()) {
            if matches!(sec_fetch_site, "same-origin" | "none") {
                return Ok(());
            } else {
                return Err(ProtectionError::SecFetchSiteUnexpectedValue(
                    sec_fetch_site.into(),
                ));
            }
        }

        if origin.is_none() && sec_fetch_site.is_none() {
            return Ok(());
        }

        let host = req.headers().get("host");

        if let Some(host) = host.and_then(|h| h.to_str().ok()) {
            if let Some(origin_url) = origin_url {
                let host_url = format!("{}://{}", origin_url.scheme(), host);
                let host_url = Url::parse(&host_url).map_err(ProtectionError::MalformedHost)?;

                if host_url == origin_url {
                    return Ok(());
                }
            }
        }

        Err(ProtectionError::CrossOriginRequest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    #[test]
    fn test_middleware_debug_trait() {
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
    fn test_add_trusted_origin() {
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
    fn test_safe_methods_are_allowed() {
        let middleware: CrossOriginProtectionMiddleware<()> = Default::default();

        let ok = ["GET", "HEAD", "OPTIONS"];

        for method in ok {
            let req = Request::builder()
                .method(method)
                .header("origin", "https://example.com")
                .body(())
                .unwrap();
            assert!(middleware.verify(&req).is_ok());
        }

        let err = ["POST", "PUT", "DELETE", "PATCH"];

        for method in err {
            let req = Request::builder()
                .method(method)
                .header("origin", "https://example.com")
                .body(())
                .unwrap();
            assert!(middleware.verify(&req).is_err());
        }
    }

    #[test]
    fn test_sec_fetch_site_same_origin_allowed() {
        let middleware: CrossOriginProtectionMiddleware<()> = Default::default();

        let request = Request::builder()
            .method("POST")
            .header("sec-fetch-site", "same-origin")
            .body(())
            .unwrap();

        assert!(middleware.verify(&request).is_ok());
    }

    #[test]
    fn test_sec_fetch_site_none_allowed() {
        let middleware: CrossOriginProtectionMiddleware<()> = Default::default();

        let request = Request::builder()
            .method("POST")
            .header("sec-fetch-site", "none")
            .body(())
            .unwrap();

        assert!(middleware.verify(&request).is_ok());
    }

    #[test]
    fn test_sec_fetch_site_cross_site_rejected() {
        let middleware: CrossOriginProtectionMiddleware<()> = Default::default();

        let request = Request::builder()
            .method("POST")
            .header("sec-fetch-site", "cross-site")
            .body(())
            .unwrap();

        assert!(middleware.verify(&request).is_err());
    }

    #[test]
    fn test_origin_matches_host_allowed() {
        let middleware: CrossOriginProtectionMiddleware<()> = Default::default();

        let request = Request::builder()
            .method("POST")
            .header("origin", "https://example.com")
            .header("host", "example.com")
            .body(())
            .unwrap();

        assert!(middleware.verify(&request).is_ok());
    }

    #[test]
    fn test_origin_matches_host_with_port_allowed() {
        let middleware: CrossOriginProtectionMiddleware<()> = Default::default();

        let request = Request::builder()
            .method("POST")
            .header("origin", "https://example.com:8080")
            .header("host", "example.com:8080")
            .body(())
            .unwrap();

        assert!(middleware.verify(&request).is_ok());
    }

    #[test]
    fn test_origin_mismatch_host_rejected() {
        let middleware: CrossOriginProtectionMiddleware<()> = Default::default();

        let request = Request::builder()
            .method("POST")
            .header("origin", "https://evil.com")
            .header("host", "example.com")
            .body(())
            .unwrap();

        assert!(middleware.verify(&request).is_err());
    }

    #[test]
    fn test_origin_mismatch_host_bypassed() {
        let layer = CrossOriginProtectionLayer::default();
        let middleware = layer
            .with_insecure_bypass(|method, uri| method == Method::POST && uri.path() == "/bypass")
            .layer(());

        let request = Request::builder()
            .method("POST")
            .uri("/bypass")
            .header("origin", "https://evil.com")
            .header("host", "example.com")
            .body(())
            .unwrap();

        assert!(middleware.verify(&request).is_ok());
    }

    #[test]
    fn test_no_origin_no_sec_fetch_site_allowed() {
        let middleware: CrossOriginProtectionMiddleware<()> = Default::default();

        let request = Request::builder().method("POST").body(()).unwrap();

        assert!(middleware.verify(&request).is_ok());
    }

    #[test]
    fn test_trusted_origin_with_sec_fetch_site_cross_site_allowed() {
        let mut middleware: CrossOriginProtectionMiddleware<()> = Default::default();
        middleware.trusted_origins.insert("https://trusted.com");

        let request = Request::builder()
            .method("POST")
            .header("sec-fetch-site", "cross-site")
            .header("origin", "https://trusted.com")
            .body(())
            .unwrap();

        assert!(middleware.verify(&request).is_ok());
    }

    #[test]
    fn test_trusted_origin_with_port_allowed() {
        let mut middleware: CrossOriginProtectionMiddleware<()> = Default::default();
        middleware
            .trusted_origins
            .insert("https://trusted.com:8080");

        let request = Request::builder()
            .method("POST")
            .header("sec-fetch-site", "cross-site")
            .header("origin", "https://trusted.com:8080")
            .body(())
            .unwrap();

        assert!(middleware.verify(&request).is_ok());
    }

    #[test]
    fn test_trusted_origin_fallback_allowed() {
        let mut middleware: CrossOriginProtectionMiddleware<()> = Default::default();
        middleware.trusted_origins.insert("https://trusted.com");

        let request = Request::builder()
            .method("POST")
            .header("origin", "https://trusted.com")
            .header("host", "different-host.com")
            .body(())
            .unwrap();

        assert!(middleware.verify(&request).is_ok());
    }
}
