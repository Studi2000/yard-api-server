// src/api_session.rs

use axum::{
    extract::State,
    response::IntoResponse,
    routing::post,
    Json,
    http::StatusCode,
};
use std::sync::Arc;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use crate::{logging::LOGGER, AppState};

#[derive(Deserialize, Serialize, Debug)]
pub struct AuditConnPayload {
    pub action: Option<String>,
    pub conn_id: Option<i64>,
    pub id: Option<String>, // target_id
    pub uuid: Option<String>,
    pub peer: Option<Vec<String>>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SessionEventPayload {
    pub event: String,
    pub uuid: String,
    pub viewer_ip: String,
    pub target_ip: String,
    pub timestamp: String,
    pub target_id: Option<String>,
}

pub async fn audit_conn_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AuditConnPayload>,
) -> impl IntoResponse {
    if LOGGER.lock().unwrap().log_level == crate::logging::LogLevel::Debug {
        if let Ok(payload_json) = serde_json::to_string(&payload) {
            LOGGER.lock().unwrap().log_with_level(
                crate::logging::LogLevel::Debug,
                &format!("[Payload] /api/audit/conn: {}", payload_json),
            );
        }
    } else {
        LOGGER.lock().unwrap().log(&format!("/api/audit/conn {:?}", payload));
    }

    let conn_id = payload.conn_id;
    let uuid = payload.uuid.as_deref();
    let target_id = payload.id.as_deref();

    // Check: nur wenn alle drei Felder gesetzt sind, tun wir etwas
    if conn_id.is_none() || uuid.is_none() || target_id.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "message": "Missing data: conn_id, uuid, or id" }))
        );
    }

    let conn_id = conn_id.unwrap();
    let uuid = uuid.unwrap();
    let target_id = target_id.unwrap();
    let now = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

    // Case 1: Neue Session (action = "new")
    if payload.action.as_deref() == Some("new") {
        let result = sqlx::query(
            "INSERT IGNORE INTO sessions (id, uuid, target_id, start_time, last_seen, end_time, viewer_id, viewer_name)
             VALUES (?, ?, ?, ?, ?, '0000-00-00 00:00:00', '', '')"
        )
        .bind(conn_id)
        .bind(uuid)
        .bind(target_id)
        .bind(&now)
        .bind(&now)
        .execute(&state.db)
        .await;

        let ok = result.as_ref().map(|r| r.rows_affected() > 0).unwrap_or(false);
        return (
            if ok { StatusCode::OK } else { StatusCode::INTERNAL_SERVER_ERROR },
            Json(serde_json::json!({ "message": if ok { "Session created" } else { "DB error" } }))
        );
    }

    // Case 2: Session update (peer: [viewer_id, viewer_name])
    if let Some(peer) = &payload.peer {
        let viewer_id = peer.get(0).map(|s| s.as_str()).unwrap_or("");
        let viewer_name = peer.get(1).map(|s| s.as_str()).unwrap_or("");
        let result = sqlx::query(
            "UPDATE sessions SET viewer_id = ?, viewer_name = ?, last_seen = ? WHERE id = ? AND uuid = ?"
        )
        .bind(viewer_id)
        .bind(viewer_name)
        .bind(&now)
        .bind(conn_id)
        .bind(uuid)
        .execute(&state.db)
        .await;

        let ok = result.as_ref().map(|r| r.rows_affected() > 0).unwrap_or(false);
        return (
            if ok { StatusCode::OK } else { StatusCode::INTERNAL_SERVER_ERROR },
            Json(serde_json::json!({ "message": if ok { "Session updated (viewer)" } else { "DB error" } }))
        );
    }

    // Case 3: Session schließen (action = "close")
    if payload.action.as_deref() == Some("close") {
        let result = sqlx::query(
            "UPDATE sessions SET end_time = ?, last_seen = ? WHERE id = ? AND uuid = ?"
        )
        .bind(&now)
        .bind(&now)
        .bind(conn_id)
        .bind(uuid)
        .execute(&state.db)
        .await;

        let ok = result.as_ref().map(|r| r.rows_affected() > 0).unwrap_or(false);
        return (
            if ok { StatusCode::OK } else { StatusCode::INTERNAL_SERVER_ERROR },
            Json(serde_json::json!({ "message": if ok { "Session closed" } else { "DB error" } }))
        );
    }

    // Default: Event wurde ignoriert, Session nicht verändert
    (
        StatusCode::OK,
        Json(serde_json::json!({ "message": "Nothing done (event ignored)" }))
    )
}

pub async fn session_event_handler(
    State(_state): State<Arc<AppState>>,
    Json(payload): Json<SessionEventPayload>,
) -> impl IntoResponse {
    if LOGGER.lock().unwrap().log_level == crate::logging::LogLevel::Debug {
        if let Ok(payload_json) = serde_json::to_string(&payload) {
            LOGGER.lock().unwrap().log_with_level(
                crate::logging::LogLevel::Debug,
                &format!("[Payload] /api/session: {}", payload_json),
            );
        }
    } else {
        LOGGER.lock().unwrap().log(&format!(
            "[POST] /api/session Payload: {:?}", payload
        ));
    }
    Json(serde_json::json!({ "message": "200 OK" }))
}

pub fn session_routes() -> axum::routing::MethodRouter<Arc<AppState>> {
    post(session_event_handler)
}

/// Route für /api/audit/conn
pub fn routes() -> axum::routing::MethodRouter<Arc<AppState>> {
    post(audit_conn_handler)
}
