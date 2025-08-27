package auth

import (
	"fmt"
	"syscall"

	"github.com/YedidyaBarGad/Aegis_vault/models"
	"github.com/YedidyaBarGad/Aegis_vault/storage"
	"golang.org/x/crypto/bcrypt"

	"golang.org/x/term"
)

// Alternative simpler implementation using golang.org/x/term directly
func ReadPasswordPrompt(prompt string) ([]byte, error) {
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %v", err)
	}
	fmt.Println() // Add newline after password input
	return password, nil
}

// PromptMasterPassword prompts the user for a master password and returns it as a byte slice.
func PromptMasterPassword(isNew bool, path string) []byte {
	password, err := ReadPasswordPrompt("Enter master password: ")
	if err != nil {
		fmt.Println("Error reading password:", err)
		return nil
	}
	fmt.Println()

	// Validate the password
	if !isNew {
		if VerifyMasterPassword(path, password) != nil {
			fmt.Println("Invalid master password.")
			return nil
		}
	}

	confirmPassword, err := ReadPasswordPrompt("Confirm master password: ")
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
	// If we reach here, the password is correct
	return nil
}

// authenticateUser checks if the provided username and password match any user in the users list.
func AuthenticateUser(username, password string, users *models.Users) bool {
	user, err := models.FindUser(username, users)
	if err != nil {
		fmt.Printf("Error finding user %s: %v\n", username, err)
		return false
	}
	if user == nil {
		fmt.Printf("User %s not found.\n", username)
		return false
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		fmt.Printf("Password mismatch for user %s: %v\n", username, err)
		return false
	}
	fmt.Printf("User %s authenticated successfully.\n", username)
	return true
}
