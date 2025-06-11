// src/api_auth.rs
use axum::{
    extract::State,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json,
    http::HeaderMap,
};
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use crate::{logging::LOGGER, AppState};
use argon2::PasswordVerifier;
use jsonwebtoken::{encode as jwt_encode, EncodingKey, Header};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use chrono::Utc;

#[derive(Deserialize, Serialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(sqlx::FromRow)]
pub struct UserRow {
    pub id: i32,
    pub username: String,
    pub password_hash: String,
    pub role: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    pub sub: i32,           // User-ID
    pub username: String,   // Username
    pub role: String,       // Rolle (admin/user)
    pub exp: i64,           // Ablauf
}

pub fn extract_claims_from_auth_header(headers: &HeaderMap, jwt_secret: &str) -> Option<Claims> {
    // Hole das Authorization-Header
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok())?;
    let token = auth_header.strip_prefix("Bearer ").unwrap_or(auth_header);

    decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &Validation::new(Algorithm::HS256)
    ).ok().map(|data| data.claims)
}

pub async fn login_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {

    // IP aus Header holen
    let client_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next()) // falls mehrere IPs im Header
        .unwrap_or("127.0.0.1"); // fallback

    if LOGGER.lock().unwrap().log_level == crate::logging::LogLevel::Debug {
        if let Ok(payload_json) = serde_json::to_string(&serde_json::json!({
            "username": &payload.username,
            "password": "***"
        })) {
            LOGGER.lock().unwrap().log_with_level(
                crate::logging::LogLevel::Debug,
                &format!("[Payload] /api/login: {}", payload_json),
            );
        }
    }

    let user = sqlx::query_as::<_, UserRow>(
        "SELECT id, username, password_hash, role FROM users WHERE username = ? LIMIT 1"
    )
    .bind(&payload.username)
    .fetch_optional(&state.db)
    .await
    .unwrap();

    if let Some(user) = user {
        if argon2::Argon2::default()
            .verify_password(payload.password.as_bytes(), &argon2::PasswordHash::new(&user.password_hash).unwrap())
            .is_ok() {

            let claims = Claims {
                sub: user.id,
                username: user.username.clone(),
                role: user.role.clone(),
                exp: (Utc::now().timestamp() + 60 * 60 * 24 * 14), // 14 Tage
            };
            let token = jwt_encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(state.jwt_secret.as_bytes())
            ).unwrap();

            LOGGER.lock().unwrap().log(&format!("Login OK: Username={} [{}]", user.username, client_ip));

            return Json(serde_json::json!({
                "access_token": token,
                "type": "access_token",
                "user": {
                    "id": user.id,
                    "name": user.username,
                    "role": user.role
                }
            }));
        }
    }

    LOGGER.lock().unwrap().log(&format!(
        "Login failed: Username={} [{}]",
        payload.username,
        client_ip
    ));

    Json(serde_json::json!({
        "access_token": null,
        "type": "access_token",
        "user": { "name": payload.username },
        "error": "Login failed!"
    }))
}

pub async fn logout_handler(
    State(_state): State<Arc<AppState>>,
    Json(payload): Json<serde_json::Value>,
) -> Response {
    if LOGGER.lock().unwrap().log_level == crate::logging::LogLevel::Debug {
        LOGGER.lock().unwrap().log_with_level(
            crate::logging::LogLevel::Debug,
            &format!("[Payload] /api/logout: {}", payload),
        );
    }


    let id = payload.get("id").and_then(|v| v.as_str()).unwrap_or("-");
    let uuid = payload.get("uuid").and_then(|v| v.as_str()).unwrap_or("-");
    LOGGER.lock().unwrap().log(&format!("Logout OK: id={}, uuid={}", id, uuid));
    Json(serde_json::json!({ "message": "Logout successful!" })).into_response()
}

pub async fn login_options_handler(
    State(_state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // LOGGER.lock().unwrap().log("[GET] /api/login-options");
    Json(serde_json::json!({
        "methods": ["password"]
    }))
}

pub fn routes() -> axum::routing::MethodRouter<Arc<AppState>> {
    post(login_handler)
}

pub fn logout_route() -> axum::routing::MethodRouter<Arc<AppState>> {
    post(logout_handler)
}

pub fn login_options_route() -> axum::routing::MethodRouter<Arc<AppState>> {
    get(login_options_handler).post(login_options_handler)
}