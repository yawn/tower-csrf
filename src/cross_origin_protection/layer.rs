use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use http::{Method, Uri};
use tower::Layer;
use tracing::debug;

use super::service::CrossOriginProtectionMiddleware;
use super::url::TrustedOrigin;
use super::{BypassFn, ConfigError, DebugFn, Origins};

/// Decorates a HTTP service with CSRF protection.
#[derive(Clone, Default)]
pub struct CrossOriginProtectionLayer {
    insecure_bypass: Option<Arc<BypassFn>>,
    trusted_origins: Origins,
}

impl Debug for CrossOriginProtectionLayer {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CrossOriginProtectionLayer")
            .field(
                "insecure_bypass",
                &self.insecure_bypass.as_ref().map(|_| DebugFn),
            )
            .field("trusted_origins", &self.trusted_origins)
            .finish()
    }
}

impl CrossOriginProtectionLayer {
    /// Adds a trusted origin which allows all requests with an `Origin` header which exactly matches
    /// the given value.
    ///
    /// Origin header values are of the form `scheme://host[:port]`.
    pub fn add_trusted_origin<S: AsRef<str>>(mut self, origin: S) -> Result<Self, ConfigError> {
        let normalized = TrustedOrigin::parse(origin.as_ref())?.into_canonical();

        debug!(origin = %normalized, "added trusted origin");

        self.trusted_origins.insert(normalized);

        Ok(self)
    }

    /// Adds a bypass function that returns `true` if the given request should bypass CSRF protection. Notes that this
    /// might be insecure.
    pub fn with_insecure_bypass<F>(mut self, predicate: F) -> CrossOriginProtectionLayer
    where
        F: Fn(&Method, &Uri) -> bool + Send + Sync + 'static,
    {
        debug!("added insecure bypass");

        self.insecure_bypass = Some(Arc::new(predicate));
        self
    }
}

impl<S> Layer<S> for CrossOriginProtectionLayer {
    type Service = CrossOriginProtectionMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CrossOriginProtectionMiddleware::new(
            inner,
            self.insecure_bypass.clone(),
            self.trusted_origins.clone(),
        )
    }
}
