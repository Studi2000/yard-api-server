<?php

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class YardApi {

    protected PDO $pdo;
    protected string $jwtSecret;
    protected string $publicKey;
    public $logging = false;

    public function __construct(PDO $pdo) {
        $this->pdo         = $pdo;
        $config            = require __DIR__ . '/../config/config.php';
        $this->jwtSecret   = $config['JWT_SECRET'];        // from config
        $this->publicKey   = $config['RD_PUBLIC_KEY'];     // raw key
    }

    /** Generate a JWT for a given user. */
    private function generateJwt($userId, $username) {
        $payload = [
            'iss' => 'YARD API',
            'sub' => $userId,
            'username' => $username,
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

            $jwt = $this->generateJwt($user['id'], $user['username']);
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
        $this->logger("/api/sysinfo", $data);

        $this->updatePeer($data);

        http_response_code(200);
        echo json_encode(['message' => 'SYSINFO_UPDATED']);
    }

    public function heartbeat() {
        $data = json_decode(file_get_contents('php://input'), true);
        $this->logger("/api/heartbeat", $data);

        $this->updatePeer($data);

        if (!empty($data['conns']) && is_array($data['conns'])) {
            $this->updateSessions($data['uuid'], $data['conns']);
        }

        // Cleanup expired Sessions
        $this->cleanupExpiredSessions();

        http_response_code(200);
        echo json_encode(['message' => 'HEARTBEAT_RECEIVED']);
    }

    // Returns an empty address book for now
    public function addressBook()
    {
        $data = json_decode(file_get_contents('php://input'), true);
        $this->logger("/api/ab", $data);

        http_response_code(200);
        echo json_encode(['list' => []]);
    }

    // Accepts any personal address book entry, but does nothing yet
    public function addressBookPersonal() {
        $data = json_decode(file_get_contents('php://input'), true);
        $this->logger("/api/ab/personal", $data);

        // Here you could store $data into the DB later
        http_response_code(200);
        echo json_encode(['message' => 'ok']);
    }

    public function auditConn() {
        $data = json_decode(file_get_contents('php://input'), true);
        $this->logger("/api/audit/conn", $data);

        $conn_id = $data['conn_id'] ?? null;
        $uuid    = $data['uuid']    ?? null;
        $target_id = $data['id']    ?? null;

        // Mandatory check
        if (!$conn_id || !$uuid || !$target_id) {
            http_response_code(400);
            echo json_encode(['message' => 'Missing data: conn_id, uuid, or id']);
            return;
        }

        // UTC-Timestamp now()
        $now_utc = gmdate('Y-m-d H:i:s');

        // Case 1: New Session (Insert)
        if (isset($data['action']) && $data['action'] === 'new') {
            $stmt = $this->pdo->prepare(
                "INSERT IGNORE INTO sessions (id, uuid, target_id, start_time, last_seen, end_time, viewer_id, viewer_name)
            VALUES (?, ?, ?, ?, ?, '0000-00-00 00:00:00', '', '')"
            );
            $ok = $stmt->execute([
                $conn_id,
                $uuid,
                $target_id,
                $now_utc,
                $now_utc
            ]);

            http_response_code($ok ? 200 : 500);
            echo json_encode(['message' => $ok ? 'Session created' : 'DB error']);
            return;
        }

        // Case 2: Update peer data (viewer_id, viewer_name)
        if (isset($data['peer']) && is_array($data['peer'])) {
            $viewer_id = $data['peer'][0] ?? '';
            $viewer_name = $data['peer'][1] ?? '';
            $stmt = $this->pdo->prepare(
                "UPDATE sessions SET viewer_id = ?, viewer_name = ?, last_seen = ? WHERE id = ? AND uuid = ?"
            );
            $ok = $stmt->execute([
                $viewer_id,
                $viewer_name,
                $now_utc,
                $conn_id,
                $uuid
            ]);
            http_response_code($ok ? 200 : 500);
            echo json_encode(['message' => $ok ? 'Session updated (viewer)' : 'DB error']);
            return;
        }

        // Case 3: Session Close (set end_time)
        if (isset($data['action']) && $data['action'] === 'close') {
            $stmt = $this->pdo->prepare(
                "UPDATE sessions SET end_time = ?, last_seen = ? WHERE id = ? AND uuid = ?"
            );
            $ok = $stmt->execute([
                $now_utc,
                $now_utc,
                $conn_id,
                $uuid
            ]);
            http_response_code($ok ? 200 : 500);
            echo json_encode(['message' => $ok ? 'Session closed' : 'DB error']);
            return;
        }

        // Default: nichts zu tun, alles ok
        http_response_code(200);
        echo json_encode(['message' => 'Nothing done (event ignored)']);
    }



    /** POST /api/logout */
    public function logout(): void {
        http_response_code(204);
    }

    public function currentUser() {
        // JWT aus Header extrahieren (wie in authorizedKeys)
        $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (!preg_match('/Bearer\s+(\S+)/', $authHeader, $m)) {
            http_response_code(401);
            echo json_encode(['message' => 'No token provided']);
            return;
        }

        try {
            $jwtData = (array)$this->verifyJwt($m[1]);
        } catch (Exception $e) {
            http_response_code(403);
            echo json_encode(['message' => 'Invalid token']);
            return;
        }

        $userId = $jwtData['sub'] ?? null;
        $username = $jwtData['username'] ?? null;

        if (!$userId || !$username) {
            http_response_code(401);
            echo json_encode(['message' => 'Invalid token payload']);
            return;
        }

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


    public function sessionEvent(): void {

        $data = json_decode(file_get_contents('php://input'), true);
        $this->logger("/api/session", $data);

        // Mandatory check
        $required = ['event', 'uuid', 'viewer_ip', 'target_ip', 'timestamp'];
        foreach ($required as $field) {
            if (empty($data[$field])) {
                http_response_code(400);
                echo json_encode(['message' => "Missing data: $field"]);
                return;
            }
        }

        // Convert MySQL timestamp
        try {
            $dt = new DateTime($data['timestamp']);
            $mysqlTimestamp = $dt->format('Y-m-d H:i:s');
        } catch (Exception $e) {
            $mysqlTimestamp = date('Y-m-d H:i:s');
        }

        $target_id = $data['target_id'] ?? null;

        $stmt = $this->pdo->prepare(
            "INSERT INTO session_events (event_type, uuid, viewer_ip, target_ip, target_id, event_time) VALUES (?, ?, ?, ?, ?, ?)"
        );
        $ok = $stmt->execute([
            $data['event'],
            $data['uuid'],
            $data['viewer_ip'],
            $data['target_ip'],
            $target_id,
            $mysqlTimestamp
        ]);

        if ($ok) {
            http_response_code(200);
            echo json_encode(['message' => 'Session event logged', 'target_id' => $data['target_id']]);
        } else {
            http_response_code(500);
            echo json_encode(['message' => 'DB error']);
        }
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

    public function logger(string $caller, array $data) {

        if($this->logging == true) {
            $data["caller"] = $caller;
            // Logging
            file_put_contents(
                'payload.log',
                date('c') . " " . print_r($data, true) . "\n",
                FILE_APPEND
            );
        }
    }

    // Update session last_seen timestamps for active connections
    private function updateSessions($uuid, $connIds): void {
        if (!is_array($connIds) || empty($connIds)) return;

        $lastSeen = gmdate('Y-m-d H:i:s');

        $stmt = $this->pdo->prepare("UPDATE sessions SET last_seen = ? WHERE id = ? AND uuid = ?");

        foreach ($connIds as $conn_id) {
            $stmt->execute([$lastSeen, $conn_id, $uuid]);
        }
    }

    // Close expired sessions where last_seen is older than 5 minutes
    private function cleanupExpiredSessions(): void {
        $cutoff = gmdate('Y-m-d H:i:s', time() - 300);

        $stmt = $this->pdo->prepare("
        UPDATE sessions
        SET end_time = last_seen
        WHERE end_time IS NULL
          AND last_seen IS NOT NULL
          AND last_seen < ?
        ");

        $stmt->execute([$cutoff]);
    }

    private function updatePeer(array $data): void {
        $id    = $data['id']    ?? null;
        $uuid  = $data['uuid']  ?? null;

        if (filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $data['ip_addr'] = '::ffff:' . $_SERVER['REMOTE_ADDR'];
        } else {
            $data['ip_addr'] = $_SERVER['REMOTE_ADDR'];
        }

        $ip_addr  = $data['ip_addr'];

        if (!$id || !$uuid) return;

        // Fetch still known data
        $stmt = $this->pdo->prepare("SELECT * FROM peers WHERE id = ?");
        $stmt->execute([$id]);
        $current = $stmt->fetch(PDO::FETCH_ASSOC);

        // Set new Data if not empty

        $hostname = !empty($data['hostname']) ? $data['hostname'] : ($current['hostname'] ?? null);
        $username = !empty($data['username']) ? $data['username'] : ($current['username'] ?? null);
        $os       = !empty($data['os'])       ? $data['os']       : ($current['os'] ?? null);
        $version  = !empty($data['version'])  ? $data['version']  : ($current['version'] ?? null);
        $cpu      = !empty($data['cpu'])      ? $data['cpu']      : ($current['cpu'] ?? null);
        $memory   = !empty($data['memory'])   ? $data['memory']   : ($current['memory'] ?? null);

        // UTC timestamp
        $lastSeen = gmdate('Y-m-d H:i:s');

        $stmt = $this->pdo->prepare("REPLACE INTO peers (id, uuid, ip_addr, hostname, username, os, version, cpu, memory, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        $stmt->execute([
            $id,
            $uuid,
            $ip_addr,
            $hostname,
            $username,
            $os,
            $version,
            $cpu,
            $memory,
            $lastSeen
        ]);
    }

    /** GET /api/version */
    public function version(): void {
        $config = require __DIR__ . '/../config/config.php';
        echo json_encode(['version' => $config['VERSION']]);
    }
}