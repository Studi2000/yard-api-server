// src/api_sysinfo.rs
use axum::{
    extract::State,
    response::IntoResponse,
    routing::post,
    Json,
    http::HeaderMap,
};
use std::sync::Arc;
use sqlx::{MySqlPool, Row};
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

fn update_if_changed(new_val: &Option<String>, old_val: Option<String>) -> Option<String> {
    match (new_val, &old_val) {
        (Some(new), Some(old)) if !new.is_empty() && new != old => Some(new.clone()),
        (Some(new), None) if !new.is_empty() => Some(new.clone()),
        (None, Some(old)) => Some(old.clone()),
        (Some(new), Some(old)) if new == old => Some(old.clone()),
        _ => old_val,
    }
}

pub async fn update_peer_sysinfo(db: &MySqlPool, payload: &SysinfoRequest, ip_addr: String) {
    if payload.id == 0 || payload.uuid.is_empty() {
        return;
    }

    // Alte Werte laden
    let row_opt = sqlx::query(
        "SELECT hostname, username, os, version, cpu, memory FROM peers WHERE id = ?"
    )
    .bind(payload.id)
    .fetch_optional(db)
    .await
    .unwrap();

    // Neue Werte berechnen
    let hostname = update_if_changed(
        &payload.hostname,
        row_opt.as_ref().and_then(|r| r.get::<Option<String>, _>("hostname")),
    ).unwrap_or_default();
    let username = update_if_changed(
        &payload.username,
        row_opt.as_ref().and_then(|r| r.get::<Option<String>, _>("username")),
    ).unwrap_or_default();
    let os = update_if_changed(
        &payload.os,
        row_opt.as_ref().and_then(|r| r.get::<Option<String>, _>("os")),
    ).unwrap_or_default();
    let version = update_if_changed(
        &payload.version,
        row_opt.as_ref().and_then(|r| r.get::<Option<String>, _>("version")),
    ).unwrap_or_default();
    let cpu = update_if_changed(
        &payload.cpu,
        row_opt.as_ref().and_then(|r| r.get::<Option<String>, _>("cpu")),
    ).unwrap_or_default();
    let memory = update_if_changed(
        &payload.memory,
        row_opt.as_ref().and_then(|r| r.get::<Option<String>, _>("memory")),
    ).unwrap_or_default();

    // If changed data elements
    let changed =
        payload.hostname.as_ref().filter(|v| !v.is_empty()) != row_opt.as_ref().and_then(|r| r.get::<Option<String>, _>("hostname")).as_ref().filter(|v| !v.is_empty())
        || payload.username.as_ref().filter(|v| !v.is_empty()) != row_opt.as_ref().and_then(|r| r.get::<Option<String>, _>("username")).as_ref().filter(|v| !v.is_empty())
        || payload.os.as_ref().filter(|v| !v.is_empty()) != row_opt.as_ref().and_then(|r| r.get::<Option<String>, _>("os")).as_ref().filter(|v| !v.is_empty())
        || payload.version.as_ref().filter(|v| !v.is_empty()) != row_opt.as_ref().and_then(|r| r.get::<Option<String>, _>("version")).as_ref().filter(|v| !v.is_empty())
        || payload.cpu.as_ref().filter(|v| !v.is_empty()) != row_opt.as_ref().and_then(|r| r.get::<Option<String>, _>("cpu")).as_ref().filter(|v| !v.is_empty())
        || payload.memory.as_ref().filter(|v| !v.is_empty()) != row_opt.as_ref().and_then(|r| r.get::<Option<String>, _>("memory")).as_ref().filter(|v| !v.is_empty());

    if changed {
        let res = sqlx::query(
            "UPDATE peers SET uuid = ?, ip_addr = ?, hostname = ?, username = ?, os = ?, version = ?, cpu = ?, memory = ? WHERE id = ? AND uuid = ?"
        )
        .bind(&payload.uuid)
        .bind(&ip_addr)
        .bind(&hostname)
        .bind(&username)
        .bind(&os)
        .bind(&version)
        .bind(&cpu)
        .bind(&memory)
        .bind(payload.id)
        .bind(&payload.uuid)
        .execute(db)
        .await;

        match res {
            Ok(r) => {
                if r.rows_affected() > 0 {
                    LOGGER.lock().unwrap().log_with_level(
                        crate::logging::LogLevel::Info,
                        &format!("/api/sysinfo: Device info successfully updated: id={}, remote_ip={}", payload.id, &ip_addr.strip_prefix("::ffff:").unwrap_or(&ip_addr)),
                    );
                }
            }
            Err(e) => {
                LOGGER.lock().unwrap().log_with_level(
                    crate::logging::LogLevel::Error,
                    &format!("update_peer_sysinfo() DB-Error: {:?}", e),
                );
            }
        }

    }
}

/// POST /api/sysinfo
pub async fn sysinfo_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<SysinfoRequest>,
) -> impl IntoResponse {

    let ip_addr = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .unwrap_or("127.0.0.1")
        .trim();

    let ip_addr = ipv4_to_ipv6(ip_addr);

    if LOGGER.lock().unwrap().log_level == crate::logging::LogLevel::Debug {
        if let Ok(payload_json) = serde_json::to_string(&payload) {
            LOGGER.lock().unwrap().log_with_level(
                crate::logging::LogLevel::Debug,
                &format!("[Payload] /api/sysinfo: {}", payload_json),
            );
        }
        // Header als String loggen
        let headers_str = format!("{:?}", headers);
        LOGGER.lock().unwrap().log_with_level(
            crate::logging::LogLevel::Debug,
            &format!("[Headers] /api/sysinfo: {}", headers_str),
        );
    }

    update_peer_sysinfo(&state.db, &payload, ip_addr).await;
    Json(serde_json::json!({ "message": "OK" }))
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

/// Router für sysinfo
pub fn routes() -> axum::routing::MethodRouter<Arc<AppState>> {
    post(sysinfo_handler)
}
