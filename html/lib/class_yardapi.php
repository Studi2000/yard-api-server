<?php
// lib/class_yardapi.php – YardApi controller class

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class YardApi {
    protected PDO $pdo;
    protected string $jwtSecret;
    protected string $publicKey;

    public function __construct(PDO $pdo) {
        $this->pdo         = $pdo;
        $config            = require __DIR__ . '/../config/config.php';
        $this->jwtSecret   = $config['JWT_SECRET'];
        $this->publicKey   = $config['RD_PUBLIC_KEY'];
    }

    /** Generate a JWT for a given user. */
    protected function generateJwt(int|string $uid, string $username): string {
        $payload = [
            'iss'      => 'yard-api',
            'sub'      => $uid,
            'username' => $username,
            'exp'      => time() + 3600,
        ];

        return JWT::encode($payload, $this->jwtSecret, 'HS256');
    }

    /** Verify a JWT and return its payload. */
    protected function verifyJwt(string $token): object {
        return JWT::decode($token, new Key($this->jwtSecret, 'HS256'));
    }

    /** Handle login request. POST /login */
    public function login(): void {
        $data = json_decode(file_get_contents('php://input'), true);
        $username = $data['username'] ?? '';
        $password = $data['password'] ?? '';

        $stmt = $this->pdo->prepare(
            'SELECT id, username, password_hash, display_name, image_url FROM users WHERE username = ?'
        );
        $stmt->execute([$username]);
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['password_hash'])) {
            $token = $this->generateJwt($user['id'], $user['username']);
            echo json_encode([
                'token'        => $token,
                'id'           => $user['username'],
                'display_name' => $user['display_name'] ?? $user['username'],
                'image_url'    => $user['image_url'] ?? ''
            ]);
            return;
        }

        http_response_code(401);
        echo json_encode(['message' => 'Login failed']);
    }

    /** Handle token validation and public key delivery. POST /authorized_keys */
    public function authorizedKeys(): void {
        $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (!preg_match('/Bearer\s+(\S+)/', $auth, $m)) {
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

        // Return the raw public key from config
        echo json_encode(['pub_key' => $this->publicKey]);
    }

    public function version(): void {
        $config = require __DIR__ . '/../config/config.php';
        echo json_encode(['version' => $config['VERSION']]);
    }

    /** Handle logout. POST /logout */
    public function logout(): void {
        http_response_code(204);
    }
}