<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/db.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

$config = require __DIR__ . '/../config/config.php';
$secret = $config['jwt_secret'];

header('Content-Type: application/json');

/**
 * Handles login and returns JWT if successful.
 */
function login(array $data, PDO $pdo, string $secret): void {
    if (empty($data['username']) || empty($data['password'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Missing username or password']);
        return;
    }

    $stmt = $pdo->prepare('SELECT * FROM users WHERE username = ?');
    $stmt->execute([$data['username']]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user || !password_verify($data['password'], $user['password_hash'])) {
        http_response_code(401);
        echo json_encode(['error' => 'Invalid credentials']);
        return;
    }

    $payload = [
        'sub' => $user['username'],
        'exp' => time() + 3600
    ];

    $jwt = JWT::encode($payload, $secret, 'HS256');

    echo json_encode(['token' => $jwt]);
}

/**
 * Validates the JWT and returns the username.
 */
function me(string $authHeader, string $secret): void {
    if (!str_starts_with($authHeader, 'Bearer ')) {
        http_response_code(401);
        echo json_encode(['error' => 'Missing or invalid Authorization header']);
        return;
    }

    $token = substr($authHeader, 7);

    try {
        $decoded = JWT::decode($token, new Key($secret, 'HS256'));
        echo json_encode(['user' => $decoded->sub]);
    } catch (Exception $e) {
        http_response_code(401);
        echo json_encode(['error' => 'Invalid token']);
    }
}

/**
 * Registers a new user.
 */
function register(array $data, PDO $pdo): void {
    if (empty($data['username']) || empty($data['password'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Missing username or password']);
        return;
    }

    $hash = password_hash($data['password'], PASSWORD_DEFAULT);

    try {
        $stmt = $pdo->prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)');
        $stmt->execute([$data['username'], $hash]);
        http_response_code(201);
        echo json_encode(['success' => true]);
    } catch (PDOException $e) {
        if (str_contains($e->getMessage(), 'UNIQUE')) {
            http_response_code(409);
            echo json_encode(['error' => 'User already exists']);
        } else {
            http_response_code(500);
            echo json_encode(['error' => 'Database error']);
        }
    }
}
