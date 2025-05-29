<<<<<<< HEAD
# YARD API Server

**YARD** = *Yet Another RustDesk API Server*

This is an open-source PHP 8.3-based REST API for managing user authentication, registration, and token validation for RustDesk clients and related tools.

> **Status:** 🚧 Work in progress – not production-ready yet

## 🧭 Goals & Scope

The goal of this project is to provide a lightweight, PHP-based API layer for managing and tracking support sessions in conjunction with the [RustDesk](https://rustdesk.com) remote desktop system.

### Key Objectives

- 🎯 **User authentication** for RustDesk clients using a custom `/api/Auth/Login` endpoint
- 🕒 **Logging of remote support sessions** including:
    - Technician ID
    - Client ID or RustDesk ID
    - Start & end timestamps
    - Session duration (for billing purposes)
- 🗂️ Optional features such as:
    - Address book or contact lists (per technician/client)
    - Team-based permissions and audit trails
- 💡 All implemented in **PHP 8.3** using a **MySQL/MariaDB backend**
- 🔐 Token-based security via **JWT (JSON Web Token)**

> This project aims to act as an **external authentication and logging service** that integrates with the RustDesk client through compatible REST endpoints.

We do **not** modify the RustDesk core or its server (`hbbs`/`hbbr`) components.  
Instead, we interface with the client-side login and track session metadata for service documentation and billing.


## 🔧 Setup (Apache + PHP 8.3)

1. Ensure Apache and PHP 8.3 are installed and active.
2. Install PHP extensions:

    ```bash
    dnf install php83 php83-pdo php83-mysqlnd php83-mbstring php83-opcache
    ```

3. Place the project into your Apache web root (e.g. `/var/www/yard-api-server`).
4. Set up your virtual host to point to the `html/` directory:

    ```apache
    DocumentRoot /var/www/yard-api-server/html
    ```

5. Make sure file permissions and ownership are correct:

    ```bash
    chown -R apache:apache /var/www/yard-api-server
    chmod -R 755 /var/www/yard-api-server
    ```

6. Create your MySQL database:

    ```sql
    CREATE DATABASE `yard-api-server` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
    ```

7. Configure database credentials in `src/db.php`.

8. Install dependencies:

    ```bash
    composer install
    ```

9. Access the API via: `https://yourdomain/`

## 📜 License

This project is licensed under the [AGPL-3.0](./LICENSE).

You must disclose source code for any modifications you deploy or distribute.

> RustDesk Server is used as a backend component and is licensed separately under the AGPL-3.0.  
> See [rustdesk/rustdesk-server](https://github.com/rustdesk/rustdesk-server) for details.

## 👤 Author

Andreas Studenski  
[webcoding24.com](https://www.webcoding24.com)
=======
# yard-api-server
Yet Another RustDesk API SERVER
>>>>>>> origin/main
