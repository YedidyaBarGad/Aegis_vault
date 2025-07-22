````markdown
# 🔐 go-passman — A Secure CLI Password Manager in Go

[![Go Version](https://img.shields.io/badge/go-1.18+-brightgreen)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Build](https://img.shields.io/badge/build-passing-brightgreen)]()
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-blue)]()

**go-passman** is a lightweight, secure, and user-friendly command-line password manager written in [Go](https://golang.org/). It allows you to store, retrieve, update, and delete login credentials encrypted with a master password using modern cryptography.

---

## ✨ Features

- 🔐 **Master Password Encryption** – Protect your vault using `scrypt` and `AES-GCM`.
- 🧱 **Local-Only Storage** – All data is stored locally in `vault.json`, encrypted at rest.
- 🔏 **Zero Dependencies** – No database or cloud required.
- 🔑 **Auto Password Generation** – Secure, random password creation on demand.
- ⚙️ **Simple CLI Interface** – Easy-to-use command-line interactions.
- 📦 **Modular Design** – Clean separation of crypto, auth, storage, and utilities.

---

## 📦 Installation

```bash
git clone https://go-passman.git
cd go-passman
go build -o passman .
````

---

## 🛠️ Usage

```bash
./passman <command>
```

### Available Commands

| Command  | Description                                  |
| -------- | -------------------------------------------- |
| `init`   | Initializes the vault with a master password |
| `add`    | Add a new credential                         |
| `get`    | Retrieve credentials for a site              |
| `delete` | Delete stored credentials                    |
| `update` | Modify existing credentials                  |

---

## 🧰 Example Workflow

```bash
./passman init      # Create your master password and empty vault
./passman add       # Add a new login
./passman get       # Fetch stored login credentials
./passman update    # Modify a site's credentials
./passman delete    # Remove a site's credentials
```

---

## 🔐 How It Works

* **Encryption**: Uses `scrypt` for key derivation, `AES-GCM` for authenticated encryption.
* **Storage**: Encrypted data saved to `vault.json` with salt and nonce prepended.
* **No Cloud**: All data lives locally, offline, and securely.

---

## 🧩 Project Structure

```
github.com/YedidyaBarGad/go-passman/
├── main.go               # CLI logic
├── pr/
│   ├── auth/             # Master password setup
│   ├── crypto/           # AES + scrypt functions
│   ├── models/           # Credential schema + validation
│   ├── storage/          # File save/load logic
│   └── util/             # CLI prompts + password generation
```

---

## ✅ Requirements

* Go 1.18+
* Compatible with macOS, Linux, and Windows

---

## ⚠️ Security Notice

This project is designed for educational and personal use. While it uses secure encryption practices, please audit the code and adapt it before using in production or storing highly sensitive data.


