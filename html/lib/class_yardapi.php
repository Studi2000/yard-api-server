<?php

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class YardApi {
    protected PDO $pdo;
    protected string $jwtSecret;
    protected string $publicKey;

    public function __construct(PDO $pdo) {
        $this->pdo         = $pdo;
        $config            = require __DIR__ . '/../config/config.php';
        $this->jwtSecret   = $config['JWT_SECRET'];        // from config
        $this->publicKey   = $config['RD_PUBLIC_KEY'];     // raw key
    }

    /** Generate a JWT for a given user. */
    private function generateJwt($userId) {
        $payload = [
            'iss' => 'YARD API',
            'sub' => $userId,
            'iat' => time(),
            'exp' => time() + (60 * 60) // 1 Stunde gültig
        ];
        return JWT::encode($payload, $this->jwtSecret, 'HS256');
    }

    /** Verify a JWT and return its payload. */
    protected function verifyJwt(string $token): object {
        return JWT::decode($token, new Key($this->jwtSecret, 'HS256'));
    }

    /** GET /api/login-options */
    public function loginOptions(): void {
        // Nur Passwort‑Login unterstützen
        $methods = ['password'];
        echo json_encode(['methods' => $methods]);
    }

    /** POST /api/login */
    public function login() {

        // Read JSON input from RustDesk
        $data = json_decode(file_get_contents('php://input'), true);

        // Extract and sanitize credentials
        $username = isset($data['username']) ? trim((string)$data['username']) : '';
        $password = isset($data['password']) ? trim((string)$data['password']) : '';

        if (!$username || !$password) {
            http_response_code(400);
            echo json_encode(['message' => 'Username and password required']);
            return;
        }

        // Fetch user from database
        $stmt = $this->pdo->prepare("SELECT * FROM users WHERE username = ? limit 0,1");
        $stmt->execute([$username]);
        $user = $stmt->fetch();

        // Verify password with Argon2i
        if ($user && password_verify($password, $user['password_hash'])) {

            $jwt = $this->generateJwt($user['id']);
            http_response_code(200);
            echo json_encode([
                'access_token' => $jwt,
                'type' => 'access_token',
                'user' => [
                    'name' => $username
                ]
            ]);

        } else {
            http_response_code(401);
            echo json_encode([
                'access_token' => null,
                'type' => 'access_token',
                'user' => [
                    'name' => $username
                ],
                'error' => 'Login failed'
            ]);
        }
    }

    /** POST /api/authorized_keys */
    public function authorizedKeys(): void {
        $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (!preg_match('/Bearer\s+(\S+)/', $authHeader, $m)) {
            http_response_code(401);
            echo json_encode(['message' => 'No token provided']);
            return;
        }

        try {
            $this->verifyJwt($m[1]);
        } catch (Exception $e) {
            http_response_code(403);
            echo json_encode(['message' => 'Invalid token']);
            return;
        }

        echo json_encode(['pub_key' => $this->publicKey]);
    }

    public function sysinfo() {
        $data = json_decode(file_get_contents('php://input'), true);

        http_response_code(200);
        echo json_encode(['message' => 'SYSINFO_UPDATED']);
    }

    public function heartbeat() {
        $data = json_decode(file_get_contents('php://input'), true);

        http_response_code(200);
        echo json_encode(['message' => 'HEARTBEAT_RECEIVED']);
    }

    // Returns an empty address book for now
    public function addressBook()
    {
        http_response_code(200);
        echo json_encode(['list' => []]);
    }

    // Accepts any personal address book entry, but does nothing yet
    public function addressBookPersonal()
    {
        $data = json_decode(file_get_contents('php://input'), true);
        // Here you could store $data into the DB later
        http_response_code(200);
        echo json_encode(['message' => 'ok']);
    }

    /** POST /api/logout */
    public function logout(): void {
        http_response_code(204);
    }

    public function currentUser() {
        // Typically, you'd use the JWT to identify the user
        // For now, just demo with static or session values

        // Example: extract user id and username from the JWT (je nach Implementierung!)
        $jwtData = $this->getJwtData();
        $userId = $jwtData['sub'] ?? 1;
        $username = $jwtData['username'] ?? 'studi';

        http_response_code(200);
        echo json_encode([
            'id' => $userId,
            'username' => $username,
            'name' => $username,
            'roles' => [],
            'groups' => [],
            'avatar' => ""
        ]);
    }

    public function deviceGroupAccessible() {

        http_response_code(200);
        echo json_encode([
            'list' => [],
            'total' => 0
        ]);
    }

    public function users() {

        http_response_code(200);
        echo json_encode([
            'list' => [],
            'total' => 0
        ]);
    }

    public function peers() {
        http_response_code(200);
        echo json_encode([
            'list' => [],
            'total' => 0
        ]);
    }

    /** GET /api/version */
    public function version(): void {
        $config = require __DIR__ . '/../config/config.php';
        echo json_encode(['version' => $config['VERSION']]);
    }
}