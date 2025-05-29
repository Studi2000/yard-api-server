<?php
require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/db.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$input = json_decode(file_get_contents('php://input'), true);
$secret = 'qNRwC4tTvQ71vQPmT8Izic94Ww9BjhH55gWo';

header('Content-Type: application/json');

if ($path === '/register' && $method === 'POST') {
    $stmt = $pdo->prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)");
    try {
        $stmt->execute([
            $input['username'],
            password_hash($input['password'], PASSWORD_BCRYPT)
        ]);
        http_response_code(201);
        echo json_encode(['message' => 'User erstellt']);
    } catch (PDOException $e) {
        http_response_code(409);
        echo json_encode(['error' => 'Benutzer existiert bereits']);
    }
    exit;
}

if ($path === '/login' && $method === 'POST') {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->execute([$input['username']]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && password_verify($input['password'], $user['password_hash'])) {
        $payload = ['sub' => $user['username'], 'exp' => time() + 3600];
        $jwt = JWT::encode($payload, $secret, 'HS256');
        echo json_encode(['token' => $jwt]);
    } else {
        http_response_code(401);
        echo json_encode(['error' => 'Falsche Zugangsdaten']);
    }
    exit;
}

if ($path === '/me' && $method === 'GET') {
    $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (str_starts_with($auth, 'Bearer ')) {
        try {
            $token = substr($auth, 7);
            $decoded = JWT::decode($token, new Key($secret, 'HS256'));
            echo json_encode(['user' => $decoded->sub]);
        } catch (Exception $e) {
            http_response_code(401);
            echo json_encode(['error' => 'Token ungültig']);
        }
    } else {
        http_response_code(401);
        echo json_encode(['error' => 'Kein Token übergeben']);
    }
    exit;
}
