// src/config.rs
use std::collections::HashMap;
use std::fs;

pub struct Config {
    pub db_user: String,
    pub db_pass: String,
    pub db_host: String,
    pub db_port: u16,
    pub db_name: String,
    pub api_port: u16,
    pub log_level: String,
    pub jwt_secret: String,
    pub rd_public_key: String,
}

impl Config {
    pub fn from_file(path: &str) -> Self {
        let content = fs::read_to_string(path).expect("Error reading config file!");
        let mut map = HashMap::new();

        for line in content.lines() {
            if let Some((k, v)) = line.split_once('=') {
                map.insert(k.trim(), v.trim());
            }
        }

        Config {
            db_user: map["DB_USER"].to_string(),
            db_pass: map["DB_PASS"].to_string(),
            db_host: map["DB_HOST"].to_string(),
            db_port: map["DB_PORT"].parse().unwrap_or(3306),
            db_name: map["DB_NAME"].to_string(),
            api_port: map["API_PORT"].parse().unwrap_or(8080),
            log_level: map.get("LOG_LEVEL").unwrap_or(&"INFO").to_string(),
            jwt_secret: map["JWT_SECRET"].to_string(),
            rd_public_key: map["RD_PUBLIC_KEY"].to_string(),
        }
    }
}
