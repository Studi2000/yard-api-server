<?php

global $pdo;
require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/lib/db.php';
require_once __DIR__ . '/lib/class_yardapi.php';

header('Content-Type: application/json');

// Parse the incoming URI and request method
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$method = $_SERVER['REQUEST_METHOD'];

// Initialize the controller
$controller = new YardApi($pdo);

// Route the request strictly for /api endpoints
switch ("{$method} {$uri}") {
    case 'GET /api/login-options':
        $controller->loginOptions();
        break;
    case 'POST /api/login':
        $controller->login();
        break;
    case 'POST /api/authorized_keys':
        $controller->authorizedKeys();
        break;
    case 'POST /api/logout':
        $controller->logout();
        break;
    case 'GET /api/version':
        $controller->version();
        break;
    case 'POST /api/sysinfo':
        $controller->sysinfo();
        break;
    case 'POST /api/heartbeat':
        $controller->heartbeat();
        break;
    case 'GET /api/ab':
        $controller->addressBook();
        break;
    case 'POST /api/ab/personal':
        $controller->addressBookPersonal();
        break;
    case 'POST /api/currentUser':
        $controller->currentUser();
        break;
    case 'GET /api/device-group/accessible':
        $controller->deviceGroupAccessible();
        break;
    case 'GET /api/users':
        $controller->users();
        break;
    case 'GET /api/peers':
        $controller->peers();
        break;
    case 'POST /api/session':
        $controller->sessionEvent();
        break;
    default:
        http_response_code(404);
        echo json_encode(['message' => 'Endpoint not found']);
        break;
}
