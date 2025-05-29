<?php
// html/api/index.php – Front controller for RustDesk Client API

// Load project configuration
require_once __DIR__ . '/../config/config.php';

// Autoload dependencies (Firebase JWT)
require_once __DIR__ . '/../vendor/autoload.php';

// Database connection
require_once __DIR__ . '/../src/db.php';

// YardApi controller class
require_once __DIR__ . '/../src/class_yardapi.php';

header('Content-Type: application/json');

$uri    = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$route  = rtrim(str_replace('/api', '', $uri), '/');
$method = $_SERVER['REQUEST_METHOD'];

$controller = new YardApi($pdo);

switch ("{$method} {$route}") {
    case 'POST /login':
        $controller->login();
        break;
    case 'POST /authorized_keys':
        $controller->authorizedKeys();
        break;
    case 'POST /logout':
        $controller->logout();
        break;
    case 'GET /version':
        $controller->version();
        break;
    default:
        http_response_code(404);
        echo json_encode(['message' => 'Endpoint not found']);
        break;
}