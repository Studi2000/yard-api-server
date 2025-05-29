<?php

require_once __DIR__ . '/../src/auth.php';
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../src/db.php';

$config = require __DIR__ . '/../config/config.php';
$secret = $config['jwt_secret'];
$pdo = require __DIR__ . '/../src/db.php';

$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

header('Content-Type: application/json');

// Normalize the path
$path = rtrim($path, '/');

switch ("$method $path") {
    case 'POST /api/auth/login':
        $data = json_decode(file_get_contents('php://input'), true);
        login($data, $pdo, $secret);
        break;

    case 'GET /api/auth/me':
        $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        me($authHeader, $secret);
        break;

    case 'POST /api/auth/register':
        $data = json_decode(file_get_contents('php://input'), true);
        register($data, $pdo);
        break;

    default:
        http_response_code(404);
        echo json_encode(['error' => 'Endpoint not found']);
}
