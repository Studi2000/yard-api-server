// src/api_sysinfo.rs
use axum::{
    extract::{State, ConnectInfo},
    response::IntoResponse,
    routing::post,
    Json,
};
use std::sync::Arc;
use std::net::SocketAddr;
use sqlx::{MySqlPool, Row};
use chrono::Utc;
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};
use crate::{logging::LOGGER, AppState};

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
pub struct SysinfoRequest {
    #[serde(deserialize_with = "de_id")]
    pub id: i32,
    pub uuid: String,
    pub hostname: Option<String>,
    pub username: Option<String>,
    pub os: Option<String>,
    pub version: Option<String>,
    pub cpu: Option<String>,
    pub memory: Option<String>,
}

/// Update peer record (wie in heartbeat, ggf. refactorbar)
async fn update_peer_sysinfo(db: &MySqlPool, payload: &SysinfoRequest, remote: SocketAddr) {
    if payload.id == 0 || payload.uuid.is_empty() {
        return;
    }
    let ip_addr = if remote.ip().is_ipv4() {
        format!("::ffff:{}", remote.ip())
    } else {
        remote.ip().to_string()
    };

    let row_opt = sqlx::query(
        "SELECT hostname, username, os, version, cpu, memory FROM peers WHERE id = ?"
    )
    .bind(payload.id)
    .fetch_optional(db)
    .await
    .unwrap();

    let merge = |new_val: &Option<String>, existing: Option<String>| {
        new_val.clone().or(existing)
    };

    let hostname = merge(
        &payload.hostname,
        row_opt.as_ref().and_then(|r| r.get::<Option<String>, _>("hostname")),
    ).unwrap_or_default();
    let username = merge(
        &payload.username,
        row_opt.as_ref().and_then(|r| r.get::<Option<String>, _>("username")),
    ).unwrap_or_default();
    let os = merge(
        &payload.os,
        row_opt.as_ref().and_then(|r| r.get::<Option<String>, _>("os")),
    ).unwrap_or_default();
    let version = merge(
        &payload.version,
        row_opt.as_ref().and_then(|r| r.get::<Option<String>, _>("version")),
    ).unwrap_or_default();
    let cpu = merge(
        &payload.cpu,
        row_opt.as_ref().and_then(|r| r.get::<Option<String>, _>("cpu")),
    ).unwrap_or_default();
    let memory = merge(
        &payload.memory,
        row_opt.as_ref().and_then(|r| r.get::<Option<String>, _>("memory")),
    ).unwrap_or_default();

    let last_seen = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let _ = sqlx::query(
        "REPLACE INTO peers (id, uuid, ip_addr, hostname, username, os, version, cpu, memory, last_seen) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(payload.id)
    .bind(&payload.uuid)
    .bind(&ip_addr)
    .bind(&hostname)
    .bind(&username)
    .bind(&os)
    .bind(&version)
    .bind(&cpu)
    .bind(&memory)
    .bind(&last_seen)
    .execute(db)
    .await;
}

/// POST /api/sysinfo
pub async fn sysinfo_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Json(payload): Json<SysinfoRequest>,
) -> impl IntoResponse {
    if LOGGER.lock().unwrap().log_level == crate::logging::LogLevel::Debug {
        if let Ok(payload_json) = serde_json::to_string(&payload) {
            LOGGER.lock().unwrap().log_with_level(
                crate::logging::LogLevel::Debug,
                &format!("[Payload] /api/sysinfo: {}", payload_json),
            );
        }
    } else {
        //LOGGER.lock().unwrap().log(&format!(
        //    "/api/sysinfo: id={}, uuid={}, hostname={:?}, username={:?}, os={:?}, version={:?}, cpu={:?}, memory={:?}",
        //    payload.id, payload.uuid, payload.hostname, payload.username, payload.os, payload.version, payload.cpu, payload.memory
        //));
    }

    update_peer_sysinfo(&state.db, &payload, remote).await;

    Json(serde_json::json!({ "message": "OK" }))
}

/// Router für sysinfo
pub fn routes() -> axum::routing::MethodRouter<Arc<AppState>> {
    post(sysinfo_handler)
}
