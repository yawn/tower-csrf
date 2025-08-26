use axum::{
    body::Body,
    error_handling::HandleErrorLayer,
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    BoxError, Router,
};
use tower::{ServiceBuilder, ServiceExt};
use tower_csrf::{CrossOriginProtectionLayer, ProtectionError};
use tracing::error;

async fn handle_error(error: BoxError) -> Response<Body> {
    if let Some(csrf) = error.downcast_ref::<ProtectionError>() {
        error!("csrf error occured: {}", csrf);
        return StatusCode::FORBIDDEN.into_response();
    }

    error!("error occured: {}", error);
    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
}

fn create_app() -> Router {
    let layer = ServiceBuilder::new()
        .layer(HandleErrorLayer::new(handle_error))
        .layer(
            CrossOriginProtectionLayer::default()
                .add_trusted_origin("https://example.com")
                .unwrap(),
        );

    Router::new()
        .route("/foo", get(|| async { "foo" }))
        .route("/bar", post(|| async { "bar" }))
        .layer(layer)
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
