use axum::{
    extract::State,
    response::IntoResponse,
    routing::post,
    Json,
    http::{StatusCode, Request},
    body::Body,
};
use std::sync::Arc;
use crate::AppState;
use crate::logging::LOGGER;
use jsonwebtoken::{decode, DecodingKey, Validation};

pub async fn authorized_keys_handler(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> impl IntoResponse {
    // Manuelle Extraktion des Bearer Tokens aus dem Header
    let token_opt = req.headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|header| {
            header
                .strip_prefix("Bearer ")
                .or_else(|| header.strip_prefix("bearer "))
                .map(|s| s.trim().to_owned())
        });

    let token = match token_opt {
        Some(token) => token,
        None => {
            LOGGER.lock().unwrap().log("/api/authorized_keys: No token provided");
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "message": "No token provided" }))
            );
        }
    };

    // Validate token
    let res = decode::<serde_json::Value>(
        &token,
        &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
        &Validation::new(jsonwebtoken::Algorithm::HS256),
    );
    if res.is_err() {
        LOGGER.lock().unwrap().log("/api/authorized_keys: Invalid token");
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "message": "Invalid token" }))
        );
    }

    LOGGER.lock().unwrap().log("/api/authorized_keys: Key delivered");
    (
        StatusCode::OK,
        Json(serde_json::json!({ "pub_key": state.rd_public_key }))
    )
}

pub fn routes() -> axum::routing::MethodRouter<Arc<AppState>> {
    post(authorized_keys_handler)
}
