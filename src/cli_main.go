//go:build cli
// +build cli

package main

import (
	"fmt"
	"os"

	"github.com/YedidyaBarGad/Aegis_vault/auth"
	"github.com/YedidyaBarGad/Aegis_vault/models"
	"github.com/YedidyaBarGad/Aegis_vault/storage"
	"github.com/YedidyaBarGad/Aegis_vault/util"
)

const vaultDir = "vaults_CLI"

// handleAdd prompts the user for site, username, and password, and adds a new credential
func handleAdd(creds []models.Credential) ([]models.Credential, error) {
	site := util.PromptInput("Enter site: ")
	username := util.PromptInput("Enter username: ")
	if site == "" || username == "" {
		return creds, fmt.Errorf("site and username cannot be empty")
	}
	if existcred := models.FindCredential(creds, site); existcred != nil {
		return creds, fmt.Errorf("Credential for this site already exist")
	}
	password, err := auth.ReadPasswordPrompt("Enter password (leave blank to generate a random one): ")
	if err != nil {
		return creds, fmt.Errorf("error reading password: %v", err)
	}
	passwordStr := string(password)
	if passwordStr == "" {
		passwordStr = util.GeneratePassword(12)
		fmt.Println("Generated password:", passwordStr)
		if !util.PromptYesNo("Use generated password?") {
			return creds, fmt.Errorf("password generation cancelled")
		}
	}

	// Create a new credential and validate it
	newCred := models.Credential{Site: site, Username: username, Password: passwordStr}
	if err := models.ValidateCredential(newCred); err != nil {
		return creds, err
	}
	return append(creds, newCred), nil
}

// handleGet retrieves and displays credentials for a given site
func handleGet(creds []models.Credential) {
	site := util.PromptInput("Enter site to retrieve credentials: ")
	cred := models.FindCredential(creds, site)
	if cred == nil {
		fmt.Println("No credentials found for site:", site)
		return
	}
	fmt.Printf("Credentials for %s:\nUsername: %s\nPassword: %s\n", cred.Site, cred.Username, cred.Password)
}

// handleDelete removes credentials for a given site
func handleDelete(creds []models.Credential) ([]models.Credential, error) {
	site := util.PromptInput("Enter site to delete credentials: ")
	if site == "" {
		return creds, fmt.Errorf("site cannot be empty")
	}
	var deleted bool
	creds, deleted = models.DeleteCredential(creds, site)
	if !deleted {
		return creds, fmt.Errorf("no credentials found for site: %s", site)
	}
	fmt.Println("Deleted credentials for", site)
	return creds, nil
}

// handleUpdate prompts the user for site, new username, and new password, and updates the credential
func handleUpdate(creds []models.Credential) ([]models.Credential, error) {
	site := util.PromptInput("Enter site to update: ")
	cred := models.FindCredential(creds, site)
	if cred == nil {
		return creds, fmt.Errorf("no credentials found for site: %s", site)
	}
	fmt.Printf("Current Username: %s\n", cred.Username)

	// Prompt for new username and password
	newUsername := util.PromptInput("Enter new username (leave blank to keep current): ")
	if newUsername == "" {
		newUsername = cred.Username
	}
	newPassword, err := auth.ReadPasswordPrompt("Enter new password (leave blank to keep current): ")
	fmt.Println()
	if err != nil {
		return creds, err
	}
	newPasswordStr := string(newPassword)
	if newPasswordStr == "" {
		newPasswordStr = cred.Password
	}

	updatedCred := models.Credential{Site: site, Username: newUsername, Password: newPasswordStr}
	if err := models.ValidateCredential(updatedCred); err != nil {
		return creds, err
	}
	// Update the credential in the list
	for i, c := range creds {
		if c.Site == site {
			creds[i] = updatedCred
			break
		}
	}
	fmt.Println("Credentials updated.")
	return creds, nil
}

// handleInit initializes a new vault for the user
func handleInit(username string) ([]models.Credential, []byte, error) {
	vaultPath := storage.GetVaultPath(vaultDir, username)

	// Ensure the vault directory exists
	if err := os.MkdirAll(vaultDir, 0700); err != nil {
		return nil, nil, fmt.Errorf("failed to create vault directory: %v", err)
	}

	fmt.Printf("Initializing vault for user '%s' at %s...\n", username, vaultPath)
	password, err := auth.SetMasterPassword(true, vaultPath, nil) // Set master password for this specific vault path
	if err != nil {
		return nil, nil, fmt.Errorf("failed to set master password: %v", err)
	}
	creds := []models.Credential{}
	if err := storage.SaveVault(vaultPath, creds, []byte(password)); err != nil {
		return nil, nil, fmt.Errorf("failed to initialize vault: %v", err)
	}
	fmt.Println("Vault initialized successfully.")
	return creds, []byte(password), nil
}

func handlechangePW(creds []models.Credential, username string) error {
	_, err := auth.SetMasterPassword(true, storage.GetVaultPath(vaultDir, username), creds)
	return err
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: Aegis_vault <username> <command>")
		fmt.Println("Commands: init, add, get, delete, update, list")
		return
	}

	username := os.Args[1]
	command := os.Args[2]

	vaultPath := storage.GetVaultPath(vaultDir, username)

	if command == "init" {
		_, _, err := handleInit(username)
		if err != nil {
			fmt.Println("Init error:", err)
		}
		return
	}

	// For all other commands, prompt for password and load vault
	password := auth.PromptMasterPassword(false, vaultPath)
	creds, err := storage.LoadVault(vaultPath, password)
	if err != nil {
		fmt.Println("Error loading vault:", err)
		fmt.Println("Ensure the vault exists and the master password is correct.")
		return
	}

	switch command {
	case "add":
		creds, err = handleAdd(creds)
	case "get":
		handleGet(creds)
	case "delete":
		creds, err = handleDelete(creds)
	case "update":
		creds, err = handleUpdate(creds)
	case "list":
		util.PrintCredentials(creds)
	case "setPW":
		err = handlechangePW(creds, username)
	default:
		fmt.Println("Unknown command:", command)
		return
	}

	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Save only for modifying commands
	if command == "add" || command == "delete" || command == "update" {
		if err := storage.SaveVault(vaultPath, creds, password); err != nil {
			fmt.Println("Error saving vault:", err)
		} else {
			fmt.Println("Vault saved.")
		}
	}
}
