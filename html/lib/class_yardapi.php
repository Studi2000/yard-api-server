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

        // Extract credentials
        $username = trim($data['username']) ?? null;
        $password = trim($data['password']) ?? null;

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

            file_put_contents('rd_login_raw.txt',
                "Response:\n" . json_encode(['token' => $jwt]),
                FILE_APPEND);

        } else {
            http_response_code(401);
            echo json_encode(['message' => 'Login failed']);
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

    /** POST /api/logout */
    public function logout(): void {
        http_response_code(204);
    }

    /** GET /api/version */
    public function version(): void {
        $config = require __DIR__ . '/../config/config.php';
        echo json_encode(['version' => $config['VERSION']]);
    }
}