package util

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/YedidyaBarGad/Aegis_vault/models"
)

// GeneratePassword generates a random password with lowercase, uppercase, digits, and special characters.
func GeneratePassword(length int) string {
	if length < 8 {
		return "Password length must be at least 8 characters"
	}

	const (
		lowercase = "abcdefghijklmnopqrstuvwxyz"
		uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		digits    = "0123456789"
		special   = "!@#$%^&*()-_=+[]{}|;:,.<>?/"
	)

	allChars := lowercase + uppercase + digits + special
	password := make([]byte, length)

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := range password {
		password[i] = allChars[r.Intn(len(allChars))]
	}

	return string(password)
}

// PrompInput prompts the user for input and returns the input as a string.
func PromptInput(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading input:", err)
		return ""
	}
	return strings.TrimSpace(input)
}

// PromptYesNo prompts the user for a yes or no answer and returns true for yes and false for no.
func PromptYesNo(prompt string) bool {
	fmt.Print(prompt + " (y/n): ")
	var input string
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading input:", err)
		return false
	}
	input = string(input[0])
	return input == "y" || input == "Y"
}

// PrintCredentials prints the credentials in a formatted way.
func PrintCredentials(creds []models.Credential) {
	if len(creds) == 0 {
		fmt.Println("No credentials found.")
		return
	}

	for _, cred := range creds {
		fmt.Printf("Site: %s\nUsername: %s\nPassword: %s\n\n", cred.Site, cred.Username, cred.Password)
	}
}

func PasswordStrength(password string) bool {
	if len(password) < 8 {
		return false
	}

	hasLower := false
	hasUpper := false
	hasDigit := false
	hasSpecial := false
	for _, char := range password {
		switch {
		case 'a' <= char && char <= 'z':
			hasLower = true
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case '0' <= char && char <= '9':
			hasDigit = true
		case strings.Contains("!@#$%^&*()-_=+[]{}|;:,.<>?/", string(char)):
			hasSpecial = true
		}
	}

	if hasLower && hasUpper && hasDigit && hasSpecial {
		return true
	} else if (hasLower || hasUpper) && (hasDigit || hasSpecial) {
		return false
	}
	return false
}

// ensureEnvFileExists checks for the presence of a .env file.
// If it does not exist, it creates one and populates it with a
// cryptographically secure keys.
func EnsureEnvFileExists() {
	envFileName := ".env"

	// Check if the file already exists.
	if _, err := os.Stat(envFileName); os.IsNotExist(err) {
		fmt.Printf("%s not found. Generating a new one...\n", envFileName)

		// Generate JWT key
		jwtKey := make([]byte, 32)
		_, err := rand.Read(jwtKey)
		if err != nil {
			fmt.Printf("Failed to generate random JWT key: %v\n", err)
			os.Exit(1)
		}
		encodedJwtKey := base64.URLEncoding.EncodeToString(jwtKey)

		// Generate encryption key
		encryptionKey := make([]byte, 32)
		_, err = rand.Read(encryptionKey)
		if err != nil {
			fmt.Printf("Failed to generate random encryption key: %v\n", err)
			os.Exit(1)
		}
		encodedEncryptionKey := base64.URLEncoding.EncodeToString(encryptionKey)

		// Construct the content to be written to the file.
		content := fmt.Sprintf("JWT_SECRET_KEY=%s\nUSERS_FILE_ENCRYPTION_KEY=%s\n", encodedJwtKey, encodedEncryptionKey)

		// Write the content to the new .env file.
		err = os.WriteFile(envFileName, []byte(content), 0600)
		if err != nil {
			fmt.Printf("Failed to write to %s: %v\n", envFileName, err)
			os.Exit(1)
		}

		fmt.Printf("Successfully created %s with new keys.\n", envFileName)
	} else if err != nil {
		fmt.Printf("Failed to check for %s: %v\n", envFileName, err)
		os.Exit(1)
	}
}
