use sqlx::{mysql::MySqlPoolOptions, MySql, Pool};

// Establishes a pooled connection to the MySQL database
pub async fn create_pool(db_url: &str) -> Pool<MySql> {
    MySqlPoolOptions::new()
        .max_connections(5)
        .connect(db_url)
        .await
        .expect("Database connection failed!")
}
