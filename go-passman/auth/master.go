package auth

import (
	"fmt"
	"syscall"

	"github.com/YedidyaBarGad/go-passman/models"

	"github.com/YedidyaBarGad/go-passman/storage"
	"github.com/YedidyaBarGad/go-passman/util"

	"golang.org/x/term"
)

// PromptMasterPassword prompts the user for a master password and returns it as a byte slice.
func PromptMasterPassword() []byte {
	fmt.Print("Enter master password: ")
	// Use term.ReadPassword to read the password without echoing it to the terminal
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Println("Error reading password:", err)
		return nil
	}
	fmt.Println()

	// Validate the password
	if VerifyMasterPassword("vault.json", password) != nil {
		fmt.Println("Invalid master password.")
		return nil
	}

	fmt.Print("Confirm master password: ")
	confirmPassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Println("Error reading password:", err)
		return nil
	}
	fmt.Println()
	// Check if the passwords match
	confirmPasswordStr := string(confirmPassword)
	passwordStr := string(password)
	if passwordStr != confirmPasswordStr {
		fmt.Println("Passwords do not match.")
		return nil
	}
	return []byte(password)
}

// VerifyMasterPassword checks if the provided master password is correct by attempting to load the vault.
func VerifyMasterPassword(path string, password []byte) error {
	// Check if the vault file exists
	if !storage.FileExists(path) {
		return fmt.Errorf("vault file does not exist at path: %s", path)
	}

	// Load the vault to check if the password is correct
	creds, err := storage.LoadVault(path, password)
	if err != nil {
		return fmt.Errorf("failed to load vault: %v", err)
	}

	// Validate credentials to ensure they can be decrypted
	for _, cred := range creds {
		if err := models.ValidateCredential(cred); err != nil {
			return fmt.Errorf("invalid credential found: %v", err)
		}
	}
	return nil
}

// SetMasterPassword encrypts an initial (possibly empty) credential list and stores it using a new password.
func SetMasterPassword(path string, creds []models.Credential) (string, error) {
	// Check if the vault file already exists
	if storage.FileExists(path) {
		return "", fmt.Errorf("vault file already exists at path: %s", path)
	}
	// Prompt for a new master password
	fmt.Println("Setting up master password for the vault.")
	var password string
	fmt.Println("No credentials found.  New credentials will be encrypted with the new master password.")
	if !util.PromptYesNo("Do you want to set a new master password?") {
		fmt.Println("No master password set. Exiting.")
		return "", nil
	}
	// Ask for the new master password until it is valid
	valid := false
	for !valid {
		password = util.PromptInput("Enter new master password: ")
		if !util.PasswordStrength(password) {
			fmt.Println("Password is not strong enough. Please try again.")
			continue
		}
		valid = true
	}

	// Confirm the new master password
	confirmPassword := util.PromptInput("Confirm new master password: ")
	if password != confirmPassword {
		return "", fmt.Errorf("master passwords do not match")
	}

	// Encrypt the credentials with the new master password
	if err := storage.SaveVault(path, creds, []byte(password)); err != nil {
		return "", fmt.Errorf("failed to save vault with new master password: %v", err)
	}
	fmt.Println("Master password set successfully.")
	return password, nil
}

func ChangeMasterPassword(path string, oldPass, newPass []byte) error {
	// Verify the old master password
	if err := VerifyMasterPassword(path, oldPass); err != nil {
		return fmt.Errorf("old master password verification failed: %v", err)
	}

	// Load the existing credentials
	creds, err := storage.LoadVault(path, oldPass)
	if err != nil {
		return fmt.Errorf("failed to load vault with old master password: %v", err)
	}

	// Save the credentials with the new master password
	if err := storage.SaveVault(path, creds, newPass); err != nil {
		return fmt.Errorf("failed to save vault with new master password: %v", err)
	}

	return nil
}
