// src/logging.rs

use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use chrono::Local;
use once_cell::sync::Lazy;
use axum::http::{HeaderMap, Method, Uri};
use std::fmt::Write as FmtWrite;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Debug,
}

impl LogLevel {
    pub fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "DEBUG" => LogLevel::Debug,
            _ => LogLevel::Info,
        }
    }
}

pub struct Logger {
    pub log_level: LogLevel,
    log_file_path: String,
}

// Diese Funktion loggt Request-Daten, nur im DEBUG-Modus
pub fn log_request_debug(
    method: &Method,
    uri: &Uri,
    query: &str,
    headers: &HeaderMap,
    body: &str,
) {
    let mut msg = String::new();
    let _ = write!(
        &mut msg,
        "API-Request: {} {}\nQuery: {}\nHeaders: {:#?}\nBody: {}\n",
        method, uri, query, headers, body
    );
    let logger = LOGGER.lock().unwrap();
    if logger.log_level == LogLevel::Debug {
        logger.log_with_level(LogLevel::Debug, &msg);
    }
}

impl Logger {
    pub fn new(log_file_path: &str, log_level: LogLevel) -> Logger {
        let dir = Path::new(log_file_path).parent().unwrap();
        create_dir_all(dir).unwrap();

        Logger {
            log_level,
            log_file_path: log_file_path.to_string(),
        }
    }

    pub fn set_level(&mut self, level: LogLevel) {
        self.log_level = level;
    }

    /// Nutze diesen Aufruf für "INFO"-Logs
    pub fn log(&self, message: &str) {
        self.log_with_level(LogLevel::Info, message);
    }

    /// Nutze diesen Aufruf für "DEBUG"-Logs und alles, was ein Level mitgeben soll
    pub fn log_with_level(&self, level: LogLevel, message: &str) {
        // Debug gibt alles aus, Info nur Info
        let should_log = match self.log_level {
            LogLevel::Debug => true, // Debug loggt alles
            LogLevel::Info => level == LogLevel::Info,
        };

        if should_log {
            let now = Local::now();
            let formatted = format!(
                "{} [{:?}] {}\n",
                now.format("%Y-%m-%d %H:%M:%S"),
                level,
                message
            );
            if let Ok(mut file) = OpenOptions::new()
                .append(true)
                .create(true)
                .open(&self.log_file_path)
            {
                let _ = file.write_all(formatted.as_bytes());
            }
        }
    }
}

// Globaler, threadsicherer Logger
pub static LOGGER: Lazy<Mutex<Logger>> = Lazy::new(|| {
    Mutex::new(Logger::new(
        "/var/log/yard-api-server/yard-api-server.log",
        LogLevel::Info,
    ))
});
