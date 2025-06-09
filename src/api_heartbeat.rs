// src/api_heartbeat.rs
use axum::{
    extract::State,
    response::IntoResponse,
    routing::post,
    Json,
};
use std::sync::Arc;
use sqlx::MySqlPool;
use chrono::{Utc, Duration};
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};
use crate::{logging::LOGGER, AppState};

/// Erlaubt Zahl oder String für "id"
pub fn de_id<'de, D>(deserializer: D) -> Result<i32, D::Error>
where
    D: Deserializer<'de>,
{
    struct IdVisitor;

    impl<'de> de::Visitor<'de> for IdVisitor {
        type Value = i32;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("string or integer")
        }
        fn visit_i64<E>(self, v: i64) -> Result<i32, E>
        where E: de::Error {
            Ok(v as i32)
        }
        fn visit_u64<E>(self, v: u64) -> Result<i32, E>
        where E: de::Error {
            Ok(v as i32)
        }
        fn visit_str<E>(self, v: &str) -> Result<i32, E>
        where E: de::Error {
            v.parse::<i32>().map_err(de::Error::custom)
        }
    }

    deserializer.deserialize_any(IdVisitor)
}

#[derive(Deserialize, Serialize, Debug)]
pub struct HeartbeatRequest {
    #[serde(deserialize_with = "de_id")]
    pub id: i32,
    pub uuid: String,
    pub conns: Option<Vec<i32>>,
}

/// Heartbeat aktualisiert nur Sitzungen und Peer-Lastseen (Peer-Details können via /api/sysinfo geschrieben werden)
async fn update_session_last_seen(db: &MySqlPool, uuid: &str, conns: &Option<Vec<i32>>) {
    let now = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    if let Some(conns) = conns {
        for &conn_id in conns {
            let _ = sqlx::query(
                "UPDATE sessions SET last_seen = ? WHERE id = ? AND uuid = ?"
            )
            .bind(&now)
            .bind(conn_id)
            .bind(uuid)
            .execute(db)
            .await;
        }
    }
}

async fn update_peer_last_seen(db: &MySqlPool, id: i32, uuid: &str, ip_addr: &str) {
    let now = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    // Versuche, das Peer zu aktualisieren (last_seen + ip_addr)
    let result = sqlx::query(
        "UPDATE peers SET last_seen = ?, ip_addr = ? WHERE id = ? AND uuid = ?"
    )
    .bind(&now)
    .bind(ip_addr)
    .bind(id)
    .bind(uuid)
    .execute(db)
    .await;

    // Falls kein Peer aktualisiert wurde, mache einen Insert mit minimalen Feldern
    if let Ok(res) = &result {
        if res.rows_affected() == 0 {
            let _ = sqlx::query(
                "INSERT INTO peers (id, uuid, last_seen, ip_addr) VALUES (?, ?, ?, ?)"
            )
            .bind(id)
            .bind(uuid)
            .bind(&now)
            .bind(ip_addr)
            .execute(db)
            .await;
        }
    }
}

/// Cleanup abgelaufener Sessions (älter als 5 Minuten)
async fn cleanup_expired_sessions(db: &MySqlPool) {
    let cutoff = (Utc::now() - Duration::minutes(5)).format("%Y-%m-%d %H:%M:%S").to_string();
    let _ = sqlx::query(
        "UPDATE sessions SET end_time = last_seen WHERE end_time IS NULL AND last_seen < ?"
    )
    .bind(&cutoff)
    .execute(db)
    .await;
}

fn ipv4_to_ipv6(ip: &str) -> String {
    // Prüft, ob es eine IPv4-Adresse ist und wandelt um
    if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
        match addr {
            std::net::IpAddr::V4(v4) => format!("::ffff:{}", v4),
            std::net::IpAddr::V6(v6) => v6.to_string(),
        }
    } else {
        ip.to_string()
    }
}


/// Handle POST /api/heartbeat
pub async fn heartbeat_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<HeartbeatRequest>,
) -> impl IntoResponse {

    let ip_addr = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .unwrap_or("127.0.0.1")
        .trim();

    let ip_addr = ipv4_to_ipv6(ip_addr);

    // Debug: Logge komplette Payload als JSON
    if LOGGER.lock().unwrap().log_level == crate::logging::LogLevel::Debug {
        // Versuche, die Payload zu serialisieren
        if let Ok(payload_json) = serde_json::to_string(&payload) {
            LOGGER.lock().unwrap().log_with_level(
                crate::logging::LogLevel::Debug,
                &format!("[Payload] /api/heartbeat: {}, IP-Addr={}", payload_json, ip_addr),
            );
        }
    } else {

       // LOGGER.lock().unwrap().log(&format!(
       //     "/api/heartbeat: id={}, uuid={}, conns={:?}",
       //     payload.id, payload.uuid, payload.conns
       // ));
   }

    update_peer_last_seen(&state.db, payload.id, &payload.uuid, &ip_addr).await;
    update_session_last_seen(&state.db, &payload.uuid, &payload.conns).await;
    cleanup_expired_sessions(&state.db).await;

    Json(serde_json::json!({ "message": "200 OK" }))
}

/// Route für /api/heartbeat
pub fn routes() -> axum::routing::MethodRouter<Arc<AppState>> {
    post(heartbeat_handler)
}
