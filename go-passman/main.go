package main

import (
	"fmt"
	"os"
	"syscall"

	"go-passman/auth"
	"go-passman/models"
	"go-passman/storage"
	"go-passman/util"

	"golang.org/x/term"
)

const vaultPath = "vault.json"

func handleAdd(creds []models.Credential) ([]models.Credential, error) {
	site := util.PromptInput("Enter site: ")
	username := util.PromptInput("Enter username: ")
	if site == "" || username == "" {
		return creds, fmt.Errorf("site and username cannot be empty")
	}
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return creds, fmt.Errorf("error reading password: %v", err)
	}
	fmt.Println()
	passwordStr := string(password)
	if passwordStr == "" {
		passwordStr = util.GeneratePassword(12)
		fmt.Println("Generated password:", passwordStr)
		if !util.PromptYesNo("Use generated password?") {
			return creds, fmt.Errorf("password generation cancelled")
		}
	}

	newCred := models.Credential{Site: site, Username: username, Password: passwordStr}
	if err := models.ValidateCredential(newCred); err != nil {
		return creds, err
	}
	return append(creds, newCred), nil
}

func handleGet(creds []models.Credential) {
	site := util.PromptInput("Enter site to retrieve credentials: ")
	cred := models.FindCredential(creds, site)
	if cred == nil {
		fmt.Println("No credentials found for site:", site)
		return
	}
	fmt.Printf("Credentials for %s:\nUsername: %s\nPassword: %s\n", cred.Site, cred.Username, cred.Password)
}

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

func handleUpdate(creds []models.Credential) ([]models.Credential, error) {
	site := util.PromptInput("Enter site to update: ")
	cred := models.FindCredential(creds, site)
	if cred == nil {
		return creds, fmt.Errorf("no credentials found for site: %s", site)
	}
	fmt.Printf("Current Username: %s\n", cred.Username)

	newUsername := util.PromptInput("Enter new username (leave blank to keep current): ")
	if newUsername == "" {
		newUsername = cred.Username
	}
	fmt.Print("Enter new password (leave blank to keep current): ")
	newPassword, err := term.ReadPassword(int(syscall.Stdin))
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

func handleInit() ([]models.Credential, []byte, error) {
	fmt.Println("Initializing vault...")
	password, err := auth.SetMasterPassword(vaultPath, nil)
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

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go-passman <command>")
		fmt.Println("Commands: init, add, get, delete, update")
		return
	}
	command := os.Args[1]

	if command == "init" {
		_, _, err := handleInit()
		if err != nil {
			fmt.Println("Init error:", err)
		}
		return
	}

	// For all other commands, prompt for password and load vault
	password := auth.PromptMasterPassword()
	creds, err := storage.LoadVault(vaultPath, password)
	if err != nil {
		fmt.Println("Error loading vault:", err)
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
