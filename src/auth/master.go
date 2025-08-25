package auth

import (
	"bufio"
	"fmt"
	"os"
	"syscall"

	"github.com/YedidyaBarGad/Aegis_vault/models"
	"github.com/YedidyaBarGad/Aegis_vault/storage"
	"github.com/YedidyaBarGad/Aegis_vault/util"
	"golang.org/x/crypto/bcrypt"

	"golang.org/x/term"
)

// readPasswordPrompt read a password from CLI
func ReadPasswordPrompt(prompt string) ([]byte, error) {
	fmt.Print(prompt)
	pw, err := term.ReadPassword(int(syscall.Stdin))
	bufio.NewReader(os.Stdin).ReadString('\n')
	return pw, err
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

func PromptNewMasterPassword(path string, creds []models.Credential) (string, error) {
	// Check if the vault file already exists
	if storage.FileExists(path) {
		return "", fmt.Errorf("vault file already exists at path: %s", path)
	}
	// Prompt for a new master password
	fmt.Println("Setting up master password for the vault.")
	fmt.Println("No credentials found.  New credentials will be encrypted with the new master password.")
	if !util.PromptYesNo("Do you want to set a new master password?") {
		fmt.Println("No master password set. Exiting.")
		return "", nil
	}
	password, err := SetMasterPassword(true, path, creds)
	return password, err
}

// SetMasterPassword encrypts an initial (possibly empty) credential list and stores it using a new password.
func SetMasterPassword(isNew bool, path string, creds []models.Credential) (string, error) {
	var password string
	// Ask for the new master password until it is valid
	valid := false
	for !valid {
		fmt.Println("Enter old password and confirm it, and than new password and confirm it")
		password = string(PromptMasterPassword(isNew, path))
		if !util.PasswordStrength(password) {
			fmt.Println("Password is not strong enough. Please try again.")
			continue
		}
		valid = true
	}

	// Encrypt the credentials with the new master password
	if err := storage.SaveVault(path, creds, []byte(password)); err != nil {
		return "", fmt.Errorf("failed to save vault with new master password: %v", err)
	}
	fmt.Println("Master password set successfully.")
	return password, nil
}

func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %v", err)
	}
	return string(hashedPassword), nil
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
