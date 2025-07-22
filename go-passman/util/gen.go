package util

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/YedidyaBarGad/go-passman/models"
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
