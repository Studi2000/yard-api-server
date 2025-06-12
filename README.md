# YARD API Server

**YARD** = *Yet Another RustDesk API Server*

A **modern, open-source REST API server written in Rust** for authentication, session logging, and future billing integration with [RustDesk](https://rustdesk.com) remote desktop environments.
**Ready for production use** for authentication and session logging in combination with your own RustDesk relay infrastructure.

**Work is ongoing!**

> **Status:** 🚀 **Production-ready** for authentication & session logging.
> More advanced features are actively developed!
>
> **Coming soon:** User management, billing, reporting, device grouping, extended auditing.

---

## 🌟 Features

* **User Authentication**

    * Secure login with Argon2i password hashing
    * Token-based session management via **JWT**
* **Session & Event Logging**

    * Logs all remote support sessions (start, end, duration)
    * Stores *viewer IP*, *target IP*, *host UUID*, and timestamps
    * Ready for reporting & billing workflows
* **RustDesk Integration**

    * Custom REST API for login and session events
    * No RustDesk source code patches required!
    * No client-side changes needed
* **Peer/Device Management**

    * Tracks all online/offline peers with complete metadata
    * Sessions are clearly mapped to RustDesk clients for audit and billing
* **Extensible Design**

    * Easily adapt or extend for your organization’s needs
* **API Security**

    * Strict JWT validation for all sensitive endpoints
    * Argon2 password hashes

---

## 🚀 Setup (Rust + MariaDB/MySQL)

1. **Install Rust (toolchain >=1.75 recommended):**

   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **Clone this repository:**

   ```bash
   git clone https://github.com/yourusername/yard-api-server.git
   cd yard-api-server
   ```

3. **Configure:**

    * Copy `../etc/yardapi.conf` in the project folder to `/etc/yardapi.conf` and fill in your database credentials, API port, JWT secret, etc.

4. **Create the database (MySQL/MariaDB):**

   ```sql
   CREATE DATABASE `yard_api_server` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   CREATE USER 'yarduser'@'127.0.0.1' IDENTIFIED BY 'YOUR-PASSWORD';
   GRANT ALL PRIVILEGES ON `yard_api_server`.* TO 'yarduser'@'127.0.0.1';
   FLUSH PRIVILEGES;
   ```

5. **Build the server:**

   ```bash
   cargo build --release
   ```

   The binary will be in `target/release/yard-api-server`.

6. **Run as service or foreground:**

   ```bash
   sudo ./target/release/yard-api-server
   ```

7. **Access your API at:**
   `http://yourdomain-or-ip:PORT/api/`

---

## 🌐 Using an SSL/TLS Proxy (Reverse Proxy)

If you are running YARD API Server behind a reverse proxy (such as **nginx**, **Apache**, or a cloud load balancer) that handles HTTPS termination, you should:

* **Forward the real client IP**: Ensure your proxy passes the original client IP to the backend using the `X-Forwarded-For` header (nginx does this by default). Example for nginx:

  ```nginx
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header Host $host;
  ```
* **Configure your API server to use this header**: YARD API Server reads `X-Forwarded-For` to log and store the correct client address (not just 127.0.0.1).

**Security note:** Only trust `X-Forwarded-For` if your API server is *only* accessible by your proxy!

---

`http://yourdomain-or-ip:PORT/api/`

---

## 🗂️ Database Structure

Example tables used by YARD API Server:

```sql
CREATE DATABASE IF NOT EXISTS `yard-api-server` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `yard-api-server`;

DROP TABLE IF EXISTS `address_books`;
CREATE TABLE `address_books` (
    `id` int(11) NOT NULL,
    `user_id` int(11) NOT NULL,
    `name` varchar(128) NOT NULL,
    `max_peer` int(11) DEFAULT 0,
    `tags` text DEFAULT NULL,
    `tag_colors` text DEFAULT NULL,
    `created_at` datetime DEFAULT NULL,
    `updated_at` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

DROP TABLE IF EXISTS `address_book_peers`;
CREATE TABLE `address_book_peers` (
    `address_book_id` int(11) NOT NULL,
    `peer_id` varchar(32) NOT NULL,
    `alias` varchar(128) DEFAULT NULL,
    `tags` varchar(255) NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

DROP TABLE IF EXISTS `peers`;
CREATE TABLE `peers` (
    `id` varchar(32) NOT NULL,
    `uuid` varchar(64) NOT NULL,
    `ip_addr` varchar(64) DEFAULT NULL,
    `hostname` varchar(100) DEFAULT NULL,
    `username` varchar(64) DEFAULT NULL,
    `os` varchar(128) DEFAULT NULL,
    `version` varchar(32) DEFAULT NULL,
    `cpu` varchar(128) DEFAULT NULL,
    `memory` varchar(32) DEFAULT NULL,
    `last_seen` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

DROP TABLE IF EXISTS `sessions`;
CREATE TABLE `sessions` (
    `id` int(11) NOT NULL,
    `uuid` varchar(64) NOT NULL,
    `start_time` datetime NOT NULL,
    `end_time` datetime NOT NULL,
    `viewer_name` varchar(32) NOT NULL,
    `viewer_id` varchar(32) NOT NULL,
    `target_id` varchar(32) NOT NULL,
    `last_seen` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
    `id` int(11) NOT NULL,
    `username` varchar(255) NOT NULL,
    `password_hash` text NOT NULL,
    `display_name` varchar(200) DEFAULT NULL,
    `role` enum('admin','user') NOT NULL DEFAULT 'user'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE `address_books`
    ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`);

ALTER TABLE `address_book_peers`
    ADD PRIMARY KEY (`address_book_id`,`peer_id`);

ALTER TABLE `peers`
    ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uniq_uuid` (`uuid`);

ALTER TABLE `sessions`
    ADD PRIMARY KEY (`id`,`uuid`);

ALTER TABLE `users`
    ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`);

ALTER TABLE `address_books`
    MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

ALTER TABLE `users`
    MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;
COMMIT;
```

---

## 🔌 API Overview

* `POST /api/login` – User login, returns JWT
* `POST /api/sysinfo` – Client meta data (updates peer status)
* `POST /api/heartbeat` – Client keepalive (updates peer status)
* `POST /api/audit/conn` – Session tracking and auditing
* `GET /api/authorized_keys` – Public key for RustDesk
* `GET /api/version` – API version info
* ...plus stubs for users, address books, device groups, etc.

---

## 🔒 Security

* **All authentication** uses strong password hashing (Argon2)
* **JWT** is required for all sensitive actions
* **Session logs** cannot be manipulated by clients

---

## 📝 License

This project is licensed under the [AGPL-3.0](./LICENSE).
You must disclose source code for any modifications you deploy or distribute.

> RustDesk Server is used as a backend component and is licensed separately under the AGPL-3.0.
> See [rustdesk/rustdesk-server](https://github.com/rustdesk/rustdesk-server) for details.

---

## 🧑‍💻 Author & Contact

**Andreas Studenski**
[https://www.webcoding24.com](https://www.webcoding24.com)
