# rdtop – YARD API Server CLI Tool

`rdtop` is a simple and extensible command-line tool for interacting with the [YARD API Server](https://github.com/Studi2000/yard-api-server).  
It is written in Rust and designed to serve as the foundation for future YARD Admin and maintenance utilities.

---

## Features

- **Fast and Lightweight:** Written in Rust for optimal performance and reliability.
- **Builds with Cargo:** Easy to compile and deploy on any modern Linux system.
- **Simple Release Workflow:** Ships with a `build.sh` script for fast building and installation.
- **Clean CLI Structure:** Ready to be extended with powerful admin and diagnostic features.
- CLI Tool is showing active peers, running and finished sessions, session duration

---

## Planned Features

This tool will be extended to provide:

- User and session management
- API health checks
- Database migrations and status
- Log inspection and troubleshooting commands
- Key/Token management
- Integration with the YARD PHP API
- And much more...

---

## Build & Install

**Prerequisites:**
- Rust toolchain (`cargo`)
- Linux system with `sudo` privileges

**Steps:**

```bash
git clone https://github.com/Studi2000/yard-api-server.git
cd yard-api-server/rdtop
./build.sh
```
---
## Configuration

Before using `rdtop`, you **must create the configuration file** at `/etc/rdtop.conf` with your database and localization settings.

### Example `/etc/rdtop.conf`

```conf
DB_USER=YOUR-DB-USER
DB_PASS=YOUR-DB-PASSWORD
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=YOUR-DB-NAME
```
---

## Locale, Language & Timezone

By default, `rdtop` uses **English** and the **UTC** timezone for all date/time formatting and output.
This is because, on most Linux systems, neither the `TZ` nor `LC_TIME` environment variables are set by default, and `LANG` is typically set to `C.UTF-8` (which is neutral/English).

### Changing language or timezone

You can influence how dates and times are displayed by setting the relevant environment variables **before** starting `rdtop`.
For example, to display everything in German and use the local time for Berlin:

```bash
export LANG=de_DE.UTF-8
export TZ=Europe/Berlin
./rdtop
```

* `LANG` controls the language and date/time format (e.g. `de_DE.UTF-8` for German, `en_GB.UTF-8` for British English, etc.).
* `TZ` controls the time zone (e.g. `Europe/Berlin`, `America/New_York`, etc.).

If these variables are **not** set, the tool will fall back to:

* **English** date/time formatting
* **UTC** time zone

> **Note:**
> You can permanently set these variables for a user in your `.bashrc`, or for services in your systemd unit files using the `Environment=` directive.

---

## 🧑‍💻 Author & Contact

**Andreas Studenski**
[https://www.webcoding24.com](https://www.webcoding24.com)

---