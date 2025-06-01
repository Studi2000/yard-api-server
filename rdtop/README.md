# rdtop – YARD API Server CLI Tool

`rdtop` is a simple and extensible command-line tool for interacting with the [YARD API Server](https://github.com/Studi2000/yard-api-server).  
It is written in Rust and designed to serve as the foundation for future YARD Admin and maintenance utilities.

---

## Features

- **Fast and Lightweight:** Written in Rust for optimal performance and reliability.
- **Builds with Cargo:** Easy to compile and deploy on any modern Linux system.
- **Simple Release Workflow:** Ships with a `build.sh` script for fast building and installation.
- **Clean CLI Structure:** Ready to be extended with powerful admin and diagnostic features.

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
