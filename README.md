# 🔐 go-passman — Secure CLI & Web Password Manager in Go

[![Go Version](https://img.shields.io/badge/go-1.24+-brightgreen)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Build](https://img.shields.io/badge/build-passing-brightgreen)]()
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-blue)]()

**go-passman** is a lightweight, secure, and user-friendly password manager written in [Go](https://golang.org/). It supports both command-line and web interfaces, allowing you to store, retrieve, update, and delete login credentials encrypted with a master password using modern cryptography.

---

## ✨ Features

- 🔐 **Master Password Encryption** – Protect your vault using `scrypt` and `AES-GCM`.
- 🧱 **Local-Only Storage** – All data is stored locally in `vault.json`, encrypted at rest.
- 🔏 **No Cloud Required** – No database or cloud dependencies.
- 🔑 **Auto Password Generation** – Secure, random password creation on demand.
- ⚙️ **Simple CLI & Web UI** – Easy-to-use command-line and browser-based interfaces.
- 📦 **Modular Design** – Clean separation of crypto, auth, storage, models, and utilities.
- 🖥️ **Web Dashboard** – Manage credentials visually with Bootstrap-powered UI.
- 🛡️ **API Access** – JSON API for credential listing.

---

## 📦 Installation

```bash
git clone https://github.com/YedidyaBarGad/go-passman.git
cd go-passman/go-passman
go build -tags cli -o go-passman.exe main.go
go build -tags web -o go-passman-web.exe web_main.go
```

---

## 🛠️ Usage

### CLI

```bash
./go-passman.exe <command>
```

### Web

```bash
./go-passman-web.exe
# Then visit http://localhost:8080 in your browser
```

### Available Commands (CLI)

| Command  | Description                                  |
| -------- | -------------------------------------------- |
| `init`   | Initializes the vault with a master password |
| `add`    | Add a new credential                         |
| `get`    | Retrieve credentials for a site              |
| `delete` | Delete stored credentials                    |
| `update` | Modify existing credentials                  |
| `list`   | List all credentials                         |

---

## 🧩 Project Structure

```
go-passman/
├── main.go                # CLI entry point
├── web_main.go            # Web server entry point
├── vault.json             # Encrypted credential vault
├── auth/                  # Master password setup & verification
│   └── master.go
├── crypto/                # AES-GCM + scrypt encryption
│   └── crypto.go
├── models/                # Credential schema & validation
│   └── credentials.go
├── storage/               # Vault file save/load logic
│   └── vault.go
├── util/                  # CLI prompts & password generation
│   └── gen.go
├── templates/             # HTML templates for web UI
│   ├── add.html
│   ├── confirm_delete.html
│   ├── dashboard.html
│   ├── delete.html
│   ├── init.html
│   ├── login.html
│   └── update.html
```

---

## ✅ Requirements

* Go 1.24+
* Compatible with macOS, Linux, and Windows

---

## ⚠️ Security Notice

This project is designed for educational and personal use. While it uses secure encryption practices, please audit the code and adapt it before using in production or storing highly sensitive data.


