# 🔐 Aegis vault — Secure CLI & Web Password Manager in Go

[![Go Version](https://img.shields.io/badge/go-1.24+-brightgreen)](https://golang.org)
[![Build](https://img.shields.io/badge/build-passing-brightgreen)]()
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-blue)]()

**Aegis vault** is a lightweight, secure, and user-friendly password manager written in [Go](https://golang.org/). It allows you to store, retrieve, update, and delete login credentials encrypted with a master password using modern cryptography. It provides both a command-line interface (CLI) for quick actions and a web interface for visual management.

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

## 🎬 Demo

![A brief demo of the Aegis Vault cli interface and its features.](https://gifyu.com/image/bNeDW)

-----

## 📦 Installation

1.  **Clone the Repository:**

    ```bash
    git clone https://github.com/YedidyaBarGad/Aegis_vault.git
    cd Aegis_vault
    ```

2.  **Build the Executables:**
    The project provides two separate executables: one for the CLI and one for the Web UI.

    ```bash
    # Build the CLI executable (e.g., Aegis_vault_CLI on Linux/macOS, Aegis_vault_CLI.exe on Windows)
    go build -tags cli -o Aegis_vault cli_main.go

    # Build the Web UI executable (e.g., Aegis_vault on Linux/macOS, Aegis_vault.exe on Windows)
    go build -tags web -o Aegis_vault web_main.go
    ```

-----


### Available Commands (CLI)

| Command  | Description                                  |
| -------- | -------------------------------------------- |
| `setPW`  | Set a new master passworf for your vault     |
| `add`    | Add a new credential to your vault           |
| `delete` | Delete stored credentials                    |
| `update` | Modify existing credentials                  |
| `list`   | List all credentials in your vault           |


-----

### Project Data & Files

`Aegis_vault` creates the following files/directories in the same location as its executables:

  * `users.json`: Stores encrypted user account information.
  * `users_data/`: A directory containing individual encrypted files for each user.

-----

## 🧩 Project Structure

```
Aegis_vault/
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

This project is designed for educational and personal use. While it employs strong cryptographic practices (`scrypt`, `AES-GCM`), **please audit the code and adapt it before using in production or storing highly sensitive data for multiple users.**\!