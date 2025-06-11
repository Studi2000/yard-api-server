// src/main.rs
use axum::{
    body::Body,
    body::to_bytes,
    Router, serve,
    routing::any,
    http::{HeaderMap, StatusCode, Method, Uri},
};
use tokio::net::TcpListener;
use std::net::SocketAddr;
use urlencoding::encode;
use std::sync::Arc;
use crate::logging::LOGGER;
use crate::logging::log_request_debug;

// Internal modules
mod config;
mod db;
mod logging;
mod api_auth;
mod api_authorized_keys;
mod api_heartbeat;
mod api_sysinfo;
mod api_session;
mod api_ab;

/// Application-wide shared state (DB pool, secrets, etc.)
#[derive(Clone)]
struct AppState {
    db: sqlx::MySqlPool,
    jwt_secret: String,
    rd_public_key: String,
}

/// CORS/Options handler für alle /api routes + Logging bei unbekannten Endpunkten
pub async fn options_handler(
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> impl axum::response::IntoResponse {
    // Body als String auslesen (ggf. leer)
    let body_bytes = to_bytes(body, 65536).await.unwrap_or_default();
    let body_str = std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8-body>");

    // Extrahiere Query-String explizit:
    let query_str = uri.query().unwrap_or("");

    log_request_debug(&method, &uri, query_str, &headers, body_str);

    // CORS-Header
    let mut response_headers = HeaderMap::new();
    response_headers.insert("Access-Control-Allow-Origin", "*".parse().unwrap());
    response_headers.insert("Access-Control-Allow-Methods", "GET, POST, OPTIONS".parse().unwrap());
    response_headers.insert("Access-Control-Allow-Headers", "Content-Type, Authorization".parse().unwrap());
    (StatusCode::OK, response_headers)
}

// Signal handling for graceful shutdown (SIGINT, SIGTERM)
use tokio::signal;
#[cfg(unix)]
use tokio::signal::unix::{signal as terminate_signal, SignalKind};

async fn shutdown_signal() {
    // Wait for CTRL+C or SIGTERM
    let ctrl = signal::ctrl_c();
    #[cfg(unix)]
    let mut term = terminate_signal(SignalKind::terminate())
        .expect("failed to install SIGTERM handler");
    #[cfg(unix)]
    tokio::select! {
        _ = ctrl => {},
        _ = term.recv() => {},
    }
    LOGGER.lock().unwrap().log("[Shutdown] API server stopped.");
}

#[tokio::main]
async fn main() {
    // Log startup event
    LOGGER.lock().unwrap().log("[Startup] API server starting...");
    let conf = config::Config::from_file("/etc/yardapi.conf");
    let log_level = logging::LogLevel::from_str(&conf.log_level);
    LOGGER.lock().unwrap().set_level(log_level);

    // URL-encode DB credentials for DSN
    let db_user_enc = encode(&conf.db_user);
    let db_pass_enc = encode(&conf.db_pass);

    // Build MySQL connection URL
    let db_url = format!(
        "mysql://{}:{}@{}:{}/{}",
        db_user_enc, db_pass_enc, conf.db_host, conf.db_port, conf.db_name
    );

    // Initialize SQL connection pool
    let db_pool = db::create_pool(&db_url).await;

    // Shared application state
    let shared_state = Arc::new(AppState {
        db: db_pool,
        jwt_secret: conf.jwt_secret,
        rd_public_key: conf.rd_public_key,
    });

    // Build the API router
    let api_router = Router::new()
        .route("/login", api_auth::routes())
        .route("/login-options", api_auth::login_options_route())
        .route("/logout", api_auth::logout_route())
        .route("/authorized_keys", api_authorized_keys::routes())
        .route("/heartbeat", api_heartbeat::routes())
        .route("/sysinfo", api_sysinfo::routes())
        .route("/audit/conn", api_session::routes())
        .route("/session", api_session::session_routes())
        .merge(api_ab::ab_routes())
        .route("/*path", any(options_handler)) // catch-all for CORS/OPTIONS
        .with_state(shared_state.clone());

    // Compose the root router, nesting /api
    let app = Router::new()
        .nest("/api", api_router);

    // Bind TCP listener to configured port
    let addr = SocketAddr::from(([0, 0, 0, 0], conf.api_port));
    let listener = TcpListener::bind(addr).await.unwrap();

    // Start server with graceful shutdown and connect info (for remote addr)
    serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}
