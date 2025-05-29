<?php
// src/db.php – Database connection setup

// Load project configuration (defines DB_HOST, DB_NAME, DB_USER, DB_PASS, JWT_SECRET, RD_PUBLIC_KEY)
$config = require __DIR__ . '/../config/config.php';

// Build DSN from individual parameters
$dsn = sprintf(
    'mysql:host=%s;dbname=%s;charset=utf8mb4',
    $config['DB_HOST'],
    $config['DB_NAME']
);

try {
    $pdo = new PDO(
        $dsn,
        $config['DB_USER'],     // e.g. 'yard_user'
        $config['DB_PASS'],     // e.g. 'secret_password'
        [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4"
        ]
    );
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['message' => 'Database connection error']);
    exit;
}