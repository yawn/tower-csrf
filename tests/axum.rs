use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    routing::{get, post},
    Router,
};
use tower::ServiceExt;
use tower_csrf::{CrossOriginProtectionLayer, ProtectionError};

fn create_app() -> Router {
    Router::new()
        .route("/foo", get(|| async { "foo" }))
        .route("/bar", post(|| async { "bar" }))
        .layer(
            CrossOriginProtectionLayer::default()
                .add_trusted_origin("https://example.com")
                .unwrap(),
        )
}

#[tokio::test]
async fn test_bar_endpoint_returns_csrf_error() {
    let app = create_app();

    let req = Request::builder()
        .method("POST")
        .uri("/bar")
        .header("origin", "https://malicious.com")
        .body(Body::empty())
        .unwrap();

    let res = app.oneshot(req).await.unwrap();

    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        res.extensions().get::<ProtectionError>(),
        Some(&ProtectionError::CrossOriginRequestFromOldBrowser),
    );
}

#[tokio::test]
async fn test_bar_endpoint_succeeds_with_trusted_origin() {
    let app = create_app();

    let req = Request::builder()
        .method("POST")
        .uri("/bar")
        .header("origin", "https://example.com")
        .body(Body::empty())
        .unwrap();

    let res = app.oneshot(req).await.unwrap();

    assert_eq!(res.status(), StatusCode::OK);

    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();

    assert_eq!(std::str::from_utf8(&body).unwrap(), "bar");
}

#[tokio::test]
async fn test_foo_endpoint_returns_foo() {
    let app = create_app();

    let req = Request::builder()
        .method("GET")
        .uri("/foo")
        .body(Body::empty())
        .unwrap();

    let res = app.oneshot(req).await.unwrap();

    assert_eq!(res.status(), StatusCode::OK);

    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();

    let body_str = std::str::from_utf8(&body).unwrap();
    assert_eq!(body_str, "foo");
}
