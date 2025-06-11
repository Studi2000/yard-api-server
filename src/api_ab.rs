use axum::{extract::State, Json, http::{HeaderMap, StatusCode}};
use axum::{Router, routing::get};
use std::sync::Arc;
use crate::{AppState, api_auth::extract_claims_from_auth_header};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::{HashMap, HashSet};
use crate::logging::LOGGER;
use chrono::Utc;
use serde_json::Value;

#[derive(Serialize, Deserialize, Debug)]
pub struct AddressBookResponse {
    pub licensed_devices: u32,
    pub data: AddressBookData,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AddressBookData {
    pub tags: Vec<String>,
    pub peers: Vec<PeerEntry>,
    pub tag_colors: Value,
}

#[derive(sqlx::FromRow)]
struct DbPeerEntry {
    pub id: String,
    pub hash: Option<String>,
    pub username: Option<String>,
    pub hostname: Option<String>,
    pub platform: Option<String>,
    pub alias: Option<String>,
    pub tags: Option<String>, // Komma-getrennt oder leer
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PeerEntry {
    pub id: String,
    pub hash: Option<String>,
    pub username: Option<String>,
    pub hostname: Option<String>,
    pub platform: Option<String>,
    pub alias: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct PostPeerEntry {
    pub id: String,
    pub hash: Option<String>,
    pub username: Option<String>,
    pub hostname: Option<String>,
    pub platform: Option<String>,
    pub alias: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct PostAddressBookData {
    pub tags: Vec<String>,
    pub peers: Vec<PostPeerEntry>,
    pub tag_colors: Option<serde_json::Value>,
}

pub async fn post_ab_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {

    let now = Utc::now().naive_utc();

    // 1. Logging
    LOGGER.lock().unwrap().log_with_level(
        crate::logging::LogLevel::Debug,
        &format!("[Payload] [Post] /api/ab: {:?}", body)
    );

    // 2. JWT prüfen
    let claims = match extract_claims_from_auth_header(&headers, &state.jwt_secret) {
        Some(c) => c,
        None => return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid or missing token"}))
        ),
    };
    let user_id = claims.sub;

    // 3. Datenstring extrahieren und deserialisieren
    let data_str = match body.get("data").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Missing data field"}))
        ),
    };

    let ab_data: PostAddressBookData = match serde_json::from_str(data_str) {
        Ok(data) => data,
        Err(e) => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("Invalid data JSON: {}", e)}))
        ),
    };

    // 4. AddressBook-ID ermitteln
    let address_book_id = match sqlx::query("SELECT id FROM address_books WHERE user_id = ? LIMIT 1")
        .bind(&user_id)
        .fetch_optional(&state.db)
        .await
        .unwrap()
    {
        Some(row) => row.get::<i32, _>("id"),
        None => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "No address book for user"}))
        ),
    };

    let tags_json = serde_json::to_string(&ab_data.tags).unwrap_or("[]".to_string());
    let tag_colors_json = serde_json::to_string(&ab_data.tag_colors).unwrap_or("{}".to_string());

    // update address_books tags, tag_colors und updated_at
    sqlx::query("UPDATE address_books SET tags = ?, tag_colors = ?, updated_at = ? WHERE id = ?")
        .bind(&tags_json)
        .bind(&tag_colors_json)
        .bind(now)
        .bind(address_book_id)
        .execute(&state.db)
        .await
        .ok();

    sqlx::query("DELETE FROM address_book_peers WHERE address_book_id = ?")
        .bind(address_book_id)
        .execute(&state.db)
        .await
        .ok();

    // 5. Nur die Mapping-Tabelle address_book_peers pflegen
    for peer in ab_data.peers {
        let tags_str = peer.tags.join(",");
        sqlx::query("INSERT INTO address_book_peers (address_book_id, peer_id, alias, tags) VALUES (?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE alias = VALUES(alias), tags = VALUES(tags)")
            .bind(address_book_id)
            .bind(&peer.id)
            .bind(&peer.alias)
            .bind(&tags_str)
            .execute(&state.db)
            .await
            .ok();
    }

    (StatusCode::OK, Json(serde_json::json!({"result": "ok"})))
}




pub async fn get_ab_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
    // 1. Parse JWT and extract user info
    let claims = match extract_claims_from_auth_header(&headers, &state.jwt_secret) {
        Some(c) => c,
        None => return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid or missing token"}))
        ),
    };
    let user_id = claims.sub;
    let username = claims.username;

    // 2. Fetch or create the address book for this user

    let address_book_id = match sqlx::query("SELECT id FROM address_books WHERE user_id = ? LIMIT 1")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await
        .unwrap()
    {
        Some(row) => row.get::<i32, _>("id"),
        None => {
            let now = Utc::now().naive_utc(); // Current UTC time as NaiveDateTime
            let insert_id = sqlx::query(
                "INSERT INTO address_books (user_id, max_peer, created_at, updated_at) VALUES (?, ?, ?, ?)"
            )
            .bind(user_id)
            .bind(10)
            .bind(now)
            .bind(now)
            .execute(&state.db)
            .await
            .unwrap()
            .last_insert_id();
            insert_id as i32
        }
    };

    // Read tags and tag_colors
    let (tags_db, tag_colors_db): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT tags, tag_colors FROM address_books WHERE id = ? LIMIT 1"
    )
    .bind(address_book_id)
    .fetch_one(&state.db)
    .await
    .unwrap_or((None, None));

    let tags: Vec<String> = match tags_db {
        Some(ref s) if !s.trim().is_empty() => serde_json::from_str(s).unwrap_or_default(),
        _ => vec![],
    };
    let tag_colors: serde_json::Value = match tag_colors_db {
        Some(ref s) if !s.trim().is_empty() => serde_json::from_str(s).unwrap_or(serde_json::json!({})),
        _ => serde_json::json!({}),
    };

    // 3. Load all peers from this address book
    let db_peers: Vec<DbPeerEntry> = sqlx::query_as::<_, DbPeerEntry>(
        r#"
            SELECT
                abp.peer_id AS id,
                p.uuid AS hash,
                COALESCE(p.username, '') AS username,
                COALESCE(p.hostname, '') AS hostname,
                COALESCE(p.os, '') AS platform,
                COALESCE(abp.alias, '') AS alias,
                COALESCE(abp.tags, '') AS tags
            FROM address_book_peers abp
            LEFT JOIN peers p ON p.id COLLATE utf8mb4_unicode_ci = abp.peer_id
            WHERE abp.address_book_id = ?
        "#
    )
    .bind(address_book_id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    // Map peers
    let peers: Vec<PeerEntry> = db_peers
        .into_iter()
        .map(|db| {
            let tag_vec: Vec<String> = db
                .tags
                .unwrap_or_default()
                .split(',')
                .filter_map(|s| {
                    let trimmed = s.trim();
                    if trimmed.is_empty() { None } else { Some(trimmed.to_string()) }
                })
                .collect();

            PeerEntry {
                id: db.id,
                hash: db.hash,
                username: db.username,
                hostname: db.hostname,
                platform: db.platform,
                alias: db.alias,
                tags: tag_vec,
            }
        })
        .collect();

    // 7. Optional debug logging
    if LOGGER.lock().unwrap().log_level == crate::logging::LogLevel::Debug {
        let token = headers
            .get("authorization")
            .and_then(|hv| hv.to_str().ok())
            .unwrap_or("<no token found>");
        let token_only = token.strip_prefix("Bearer ").unwrap_or(token);

        LOGGER.lock().unwrap().log_with_level(
            crate::logging::LogLevel::Debug,
            &format!(
                "[Get] /api/ab: User_ID={}, Username={}, AddressBook_ID={}, Bearer={}",
                user_id, username, address_book_id, token_only
            )
        );
    }

    // 8. Build the RustDesk-compatible response (data is a JSON string)
    let ab_data = AddressBookData {
        tags,
        peers,
        tag_colors,
    };
    let data_str = serde_json::to_string(&ab_data).unwrap();

    let response_json = serde_json::json!({ "data": data_str });

    (StatusCode::OK, Json(response_json))
}


pub fn ab_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/ab", get(get_ab_handler).post(post_ab_handler))
}
