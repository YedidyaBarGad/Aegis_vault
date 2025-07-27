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
    go build -tags cli -o go-passman main.go

    # Build the Web UI executable (e.g., go-passman-web on Linux/macOS, go-passman-web.exe on Windows)
    go build -tags web -o go-passman-web web_main.go
    ```

    *(Note: You can omit the `.exe` suffix if building on Linux/macOS, as `go build` will automatically name it correctly for the target OS.)*

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
| `get`    | Retrieve credentials for a specific site      |
| `delete` | Delete stored credentials                    |
| `update` | Modify existing credentials                  |
| `list`   | List all credentials in your vault            |
| `chpasswd` | Change your master password                  |
| `login`  | Logs in a user for a CLI session              |

*(Note: The `init` command listed in your old README is replaced by `register` for user accounts, and vault initialization happens per user within the `auth` flow.)*

-----

### Project Data & Files

`go-passman` creates the following files/directories in the same location as its executables:

  * `.passman_key`: The crucial application-wide encryption key (generated automatically on first run). **Do not commit this to Git\!**
  * `users.json`: Stores encrypted user account information.
  * `users_data/`: A directory containing individual encrypted `vault.json` files for each user.

These files are automatically `.gitignore`'d in the repository to prevent accidental leakage.

-----

## 🧩 Project Structure

```
go-passman/
├── main.go                # CLI entry point (handles commands like register, add, get, etc.)
├── web_main.go            # Web server entry point (handles web routes and API)
├── .passman_key           # Auto-generated application-wide encryption key (NOT committed)
├── users.json             # Encrypted list of registered users
├── users_data/            # Directory containing individual user vaults
│   └── <username>_vault.json # Encrypted credential vault for a specific user
├── auth/                  # User authentication, master password handling, vault key derivation
│   └── auth.go
├── crypto/                # AES-GCM encryption/decryption, random byte generation
│   └── crypto.go
├── models/                # Data structures for User, Credential, and related logic
│   ├── users.go           # Logic for loading/saving users.json and app key
│   └── vault.go           # Logic for loading/saving individual vault.json (should be credentials.go?)
├── util/                  # CLI prompts, password generation, helper functions
│   └── util.go            # Renamed from gen.go for broader utility functions
├── templates/             # HTML templates for web UI
│   ├── add.html
│   ├── confirm_delete.html
│   ├── dashboard.html
│   ├── delete.html
│   ├── init.html          # Likely for initial user registration, or master password setup
│   ├── login.html
│   └── update.html
├── static/                # Static assets like CSS, JS, images for web UI
```

-----

## ✅ Requirements

  * Go 1.24+
  * Compatible with macOS, Linux, and Windows

-----

## ⚠️ Security Notice

This project is designed for educational and personal use. While it employs strong cryptographic practices (`scrypt`, `AES-GCM`), **please audit the code and adapt it before using in production or storing highly sensitive data for multiple users.** Always back up your `.passman_key` and individual `vault.json` files\!