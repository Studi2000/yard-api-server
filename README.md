# YARD API Server

**YARD** = *Yet Another RustDesk API Server*

A **modern, open-source PHP 8.3 REST API** for authentication, billing, and session logging for [RustDesk](https://rustdesk.com) remote desktop environments.
**Ready for basic use** in combination with RustDesk and your own relay server patch.

**Work is still in progress!**

> **Status:** 🚀 **Production-ready** for authentication, session tracking & billing.
> Active development for advanced features!

---

## 🌟 Features

* **User Authentication**

    * Secure login with Argon2i password hash
    * Token-based session management via **JWT**
* **Session Event Logging**

    * Logs all remote support sessions (start, end, duration)
    * Stores *viewer IP*, *target IP*, *host (target) ID* (UUID), and timestamps
    * Ready for reporting & billing workflows
* **Integration with RustDesk**

    * Uses a custom REST interface for login and session data
    * You find all changes 
    * *Requires a small patch in* [`relay_server.rs`](https://github.com/Studi2000/yard-api-server/tree/master/patch/rustdesk-server) *to forward session events*
* **Device & Peer Management**

    * Tracks all online/offline peers (clients) with full metadata
    * Maps sessions to RustDesk clients for transparent user billing
* **Team & User Management**

    * User endpoints ready for future expansion (groups, address books, permissions)
* **API Security**

    * Strict JWT validation for all sensitive endpoints
* **Extensible Design**

    * Easily adapt or extend for your organization’s needs

---

### 🔧 Environment Variable: `YARD_API_URL`

Your patched `relay_server.rs` reads the **API server URL** from the environment variable `YARD_API_URL`.
You must provide this variable to your `hbbr` systemd service (or when starting the binary), for example:

```ini
[Service]
Environment=YARD_API_URL=https://your-api-server.example.com/api/session
```

* **If not set**, no session events will be sent to your PHP backend.
* You can change the target at any time without rebuilding the relay server.
* This makes your session event logging endpoint flexible and portable.

**You do NOT need to patch any RustDesk clients!**

---

## 🚀 Setup (Apache + PHP 8.3 + MariaDB/MySQL)

1. **Install Apache, PHP 8.3, Composer:**

   ```bash
   dnf install php83 php83-pdo php83-mysqlnd php83-mbstring php83-opcache composer
   ```
2. **Clone this project** into your Apache web root, e.g. `/var/www/yard-api-server`
3. **Set up your VirtualHost** to point to the `html/` directory:

   ```apache
   DocumentRoot /var/www/yard-api-server/html
   ```
4. **File permissions** (if running as `apache:apache`):

   ```bash
   chown -R apache:apache /var/www/yard-api-server
   chmod -R 755 /var/www/yard-api-server
   ```
5. **Create MySQL/MariaDB Database:**

   ```sql
   CREATE DATABASE `yard-api-server` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   ```
6. **Configure:**

    * Rename `config/config.example.php` → `config/config.php`
    * Enter your database credentials and JWT secret.
7. **Install PHP dependencies:**

   ```bash
   composer install
   ```
8. **Ready!**
   Access your API at `http://yourdomain-or-ip/`

---

## 🗂️ Database Structure

Below are the main tables used by YARD API Server for tracking users, peers, and session events.

```sql
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `session_events` (
     `id` int(11) NOT NULL,
     `event_type` varchar(10) NOT NULL,
     `uuid` varchar(64) NOT NULL,
     `viewer_ip` varchar(64) NOT NULL,
     `target_ip` varchar(64) NOT NULL,
     `target_id` varchar(32) DEFAULT NULL,
     `event_time` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `users` (
     `id` int(11) NOT NULL,
     `username` varchar(255) NOT NULL,
     `password_hash` text NOT NULL,
     `display_name` varchar(200) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE `peers`
    ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uniq_uuid` (`uuid`);

ALTER TABLE `session_events`
    ADD PRIMARY KEY (`id`),
  ADD KEY `uuid` (`uuid`);

ALTER TABLE `users`
    ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`);

ALTER TABLE `session_events`
    MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

ALTER TABLE `users`
    MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;
COMMIT;
```

---

## 🔌 API Overview

* `POST /api/login` – User login, returns JWT
* `POST /api/heartbeat` – Client keepalive (updates peer status)
* `POST /api/session` – Session event log (triggered by relay\_server.rs patch)
* `GET /api/authorized_keys` – Public key for RustDesk
* `GET /api/version` – API version info
* *…plus stub endpoints for address books, users, device groups etc.*

---

## 🔒 Security

* **All authentication** uses strong password hashing (Argon2i)
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

---
