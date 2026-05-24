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

mod cross_origin_protection;

pub use cross_origin_protection::{
    ConfigError, CrossOriginProtectionLayer, CrossOriginProtectionMiddleware, ProtectionError,
    ResponseFuture,
};
