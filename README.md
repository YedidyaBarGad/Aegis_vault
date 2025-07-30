# 🔐 go-passman — Secure CLI & Web Password Manager in Go

[![Go Version](https://img.shields.io/badge/go-1.24+-brightgreen)](https://golang.org)
[![Build](https://img.shields.io/badge/build-passing-brightgreen)]()
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-blue)]()

**go-passman** is a lightweight, secure, and user-friendly password manager written in [Go](https://golang.org/). It allows you to store, retrieve, update, and delete login credentials encrypted with a master password using modern cryptography. It provides both a command-line interface (CLI) for quick actions and a web interface for visual management.

-----

## ✨ Features

  - 🔐 **Master Password Encryption** – Protect your vault and individual credentials using `scrypt` for key derivation and `AES-GCM` for symmetric encryption.
  - 📂 **Local-Only Storage** – All data, including user accounts (`users.json`) and individual vaults (`vault.json`), is stored locally, encrypted at rest.
  - 🔏 **No Cloud Required** – No external database or cloud dependencies.
  - 🔑 **Automatic Key Generation** – Automatically generates a unique application-wide encryption key on first run for seamless setup.
  - ⚙️ **Simple CLI & Web UI** – Easy-to-use command-line and browser-based interfaces.
  - 📦 **Modular Design** – Clean separation of crypto, auth, models, and utilities.
  - 🖥️ **Web Dashboard** – Manage credentials visually with a clean, Bootstrap-powered UI.
  - 🛡️ **API Access** – Provides a JSON API for credential listing (via the web interface).

-----

## 📦 Installation

1.  **Clone the Repository:**

    ```bash
    git clone https://github.com/YedidyaBarGad/go-passman.git
    cd go-passman
    ```

2.  **Build the Executables:**
    The project provides two separate executables: one for the CLI and one for the Web UI.

    ```bash
    # Build the CLI executable (e.g., go-passman on Linux/macOS, go-passman.exe on Windows)
    go build -tags cli -o go-passman cli_main.go

    # Build the Web UI executable (e.g., go-passman-web on Linux/macOS, go-passman-web.exe on Windows)
    go build -tags web -o go-passman-web web_main.go
    ```

-----

## 🛠️ Usage

### Important Setup Note (First Run)

When you run either the CLI or Web executable for the **very first time**, `go-passman` will **automatically generate a unique, cryptographically secure application-wide encryption key**. This key is essential for encrypting your `users.json` file.

  * This key will be saved in a file named `.passman_key` in the same directory as the executable.
  * The application will display a **critical warning** with instructions to back up this file.
  * **🚨 YOU MUST BACK UP THIS `.passman_key` FILE\! 🚨** If this file is lost or corrupted, all your user accounts and their associated vaults will become **UNRECOVERABLE**.

### CLI Usage

Execute the CLI application from your terminal:

```bash
./go-passman <command>
```

### Web Usage

Start the web server and then access it via your browser:

```bash
./go-passman-web
# Then open your web browser and navigate to: http://localhost:8080
```

### Available Commands (CLI)

| Command  | Description                                  |
| -------- | -------------------------------------------- |
| `register`| Registers a new user account with a master password (first step for new users) |
| `add`    | Add a new credential to your vault            |
| `delete` | Delete stored credentials                    |
| `update` | Modify existing credentials                  |
| `list`   | List all credentials in your vault            |
| `login`  | Logs in a user for a CLI session              |


-----

### Project Data & Files

`go-passman` creates the following files/directories in the same location as its executables:

  * `.passman_key`: The crucial application-wide encryption key (generated automatically on first run). **Do not commit this to Git\!**
  * `users.json`: Stores encrypted user account information.
  * `users_data/`: A directory containing individual encrypted `vault.json` files for each user.

-----

## 🧩 Project Structure

```
go-passman/
├── cli_main.go            # CLI entry point
├── web_main.go            # Web server entry point
├── auth/                  # Master password setup & verification
│   └── master.go
├── crypto/                # AES-GCM + scrypt encryption
│   └── crypto.go
├── models/                # Credential schema & validation
│   └── credentials.go
├── storage/               # Vault file save/load logic
│   └── vault.go
├── util/                  # CLI prompts & password generation
│   └── gen.go
├── templates/             # HTML templates for web UI
│   ├── add.html
│   ├── confirm_delete.html
│   ├── dashboard.html
│   ├── delete.html
│   ├── init.html
│   ├── login.html
│   └── update.html

```
---

## ✅ Requirements

  * Go 1.24+
  * Compatible with macOS, Linux, and Windows

-----

## ⚠️ Security Notice

This project is designed for educational and personal use. While it employs strong cryptographic practices (`scrypt`, `AES-GCM`), **please audit the code and adapt it before using in production or storing highly sensitive data for multiple users.** Always back up your `.passman_key` and individual `vault.json` files\!