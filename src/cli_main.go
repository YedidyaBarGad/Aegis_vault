//go:build cli

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/YedidyaBarGad/Aegis_vault/auth"
	"github.com/YedidyaBarGad/Aegis_vault/models"
	"github.com/YedidyaBarGad/Aegis_vault/storage"
	"github.com/YedidyaBarGad/Aegis_vault/util"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

const usersDir = "users_data"
const allUsersPath = "users_data/users.json"

var allUsers *models.Users

func init() {
	// Ensure users data directory exists
	if err := os.MkdirAll(usersDir, 0755); err != nil {
		fmt.Printf("Failed to create users data directory: %v\n", err)
		os.Exit(1)
	}

	// Ensure .env file exists and load environment variables
	util.EnsureEnvFileExists()
	godotenv.Load()

	// Load existing users or initialize empty users list
	loadedUsers, err := models.LoadUsers(allUsersPath)
	if err != nil || loadedUsers == nil {
		allUsers = &models.Users{
			Number: 0,
			Users:  []models.User{},
		}
	} else {
		allUsers = loadedUsers
	}
}

// handleAdd prompts the user for site, username, and password, and adds a new credential
func handleAdd(creds []models.Credential) ([]models.Credential, error) {
	site := util.PromptInput("Enter site: ")
	username := util.PromptInput("Enter username: ")
	if site == "" || username == "" {
		return creds, fmt.Errorf("site and username cannot be empty")
	}
	if existcred := models.FindCredential(creds, site); existcred != nil {
		return creds, fmt.Errorf("credential for this site already exists")
	}
	password, err := auth.ReadPasswordPrompt("Enter password (leave blank to generate a random one): ")
	if err != nil {
		return creds, fmt.Errorf("error reading password: %v", err)
	}
	passwordStr := string(password)
	if passwordStr == "" {
		passwordStr = util.GeneratePassword(16)
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

// handleInit initializes a new vault for the user and saves user data.
func handleInit(username string) ([]models.Credential, []byte, error) {
	// Check if the username already exists.
	if allUsers == nil {
		allUsers = &models.Users{Number: 0, Users: []models.User{}}
	}
	if user, _ := models.FindUser(username, allUsers); user != nil {
		return nil, nil, fmt.Errorf("username '%s' already exists", username)
	}

	// Prompt for password
	password, err := auth.ReadPasswordPrompt("Enter new master password: ")
	if err != nil {
		return nil, nil, fmt.Errorf("error reading password: %v", err)
	}

	// Password strength check
	if !util.PasswordStrength(string(password)) {
		return nil, nil, fmt.Errorf("password must be at least 8 characters long and include uppercase, lowercase, a digit, and a special character")
	}

	// Confirm password
	confirmPassword, err := auth.ReadPasswordPrompt("Confirm master password: ")
	if err != nil {
		return nil, nil, fmt.Errorf("error reading confirmation password: %v", err)
	}
	if string(password) != string(confirmPassword) {
		return nil, nil, fmt.Errorf("passwords do not match")
	}

	// Hash the password for the users.json file
	hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to hash password: %v", err)
	}

	// Get the vault path
	userVaultFileName := storage.GetVaultPath(username, "")
	userVaultPath := filepath.Join(usersDir, userVaultFileName)

	// Initialize the vault file (it will be empty)
	creds := []models.Credential{}
	if err := storage.SaveVault(userVaultPath, creds, password); err != nil {
		return nil, nil, fmt.Errorf("failed to initialize vault: %v", err)
	}

	// Add the user to the central users list
	if err := models.AddUser(username, string(hashedPassword), userVaultFileName, allUsersPath, allUsers); err != nil {
		// If adding the user fails, try to clean up the created vault file to avoid orphaned data.
		os.Remove(userVaultPath)
		return nil, nil, fmt.Errorf("failed to save new user: %v", err)
	}

	fmt.Printf("Vault initialized successfully for user '%s'.\n", username)
	return creds, password, nil
}

// handleChangePW handles password changes for CLI users
func handleChangePW(creds []models.Credential, username string) error {
	// Prompt for old password
	oldPassword, err := auth.ReadPasswordPrompt("Enter current master password: ")
	if err != nil {
		return fmt.Errorf("error reading current password: %v", err)
	}

	// Verify old password
	if !auth.AuthenticateUser(username, string(oldPassword), allUsers) {
		return fmt.Errorf("current password is incorrect")
	}

	// Prompt for new password
	newPassword, err := auth.ReadPasswordPrompt("Enter new master password: ")
	if err != nil {
		return fmt.Errorf("error reading new password: %v", err)
	}

	// Password strength check
	if !util.PasswordStrength(string(newPassword)) {
		return fmt.Errorf("new password must be at least 8 characters long and include uppercase, lowercase, a digit, and a special character")
	}

	// Confirm new password
	confirmPassword, err := auth.ReadPasswordPrompt("Confirm new master password: ")
	if err != nil {
		return fmt.Errorf("error reading confirmation password: %v", err)
	}
	if string(newPassword) != string(confirmPassword) {
		return fmt.Errorf("new passwords do not match")
	}

	// Hash the new password
	hashedPassword, err := bcrypt.GenerateFromPassword(newPassword, bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash new password: %v", err)
	}

	// Update user's password hash in users list
	user, err := models.FindUser(username, allUsers)
	if err != nil || user == nil {
		return fmt.Errorf("user not found: %v", err)
	}

	// Update password hash in the users list
	for i, u := range allUsers.Users {
		if u.Username == username {
			allUsers.Users[i].Password = string(hashedPassword)
			break
		}
	}

	// Save updated users list
	if err := models.SaveUsers(allUsersPath, allUsers); err != nil {
		return fmt.Errorf("failed to save updated user data: %v", err)
	}

	// Re-encrypt vault with new password
	userVaultPath := filepath.Join(usersDir, user.VaultFileName)
	if err := storage.SaveVault(userVaultPath, creds, newPassword); err != nil {
		return fmt.Errorf("failed to re-encrypt vault with new password: %v", err)
	}

	fmt.Println("Master password changed successfully.")
	return nil
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: <username> <command>")
		fmt.Println("Commands: init, add, get, delete, update, list, setPW")
		return
	}

	username := os.Args[1]
	command := os.Args[2]

	if command == "init" {
		_, _, err := handleInit(username)
		if err != nil {
			fmt.Println("Init error:", err)
		}
		return
	}

	// For all other commands, prompt for password and load vault
	password := auth.PromptMasterPassword(false, storage.GetVaultPath(username, usersDir))

	// Authenticate user
	if !auth.AuthenticateUser(username, string(password), allUsers) {
		fmt.Println("Authentication failed: Invalid username or password.")
		return
	}

	// Load user data to get the vault path
	user, err := models.FindUser(username, allUsers)
	if err != nil || user == nil {
		fmt.Println("User not found:", err)
		return
	}

	vaultPath := filepath.Join(usersDir, user.VaultFileName)

	// Load vault
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
		err = handleChangePW(creds, username)
		if err == nil {
			// If password change was successful, we need to reload with new password
			newPassword, readErr := auth.ReadPasswordPrompt("Re-enter new master password to continue: ")
			if readErr != nil {
				fmt.Println("Error reading new password:", readErr)
				return
			}
			creds, err = storage.LoadVault(vaultPath, newPassword)
			if err != nil {
				fmt.Println("Error reloading vault with new password:", err)
				return
			}
			password = newPassword
		}
	default:
		fmt.Println("Unknown command:", command)
		fmt.Println("Available commands: init, add, get, delete, update, list, setPW")
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
			fmt.Println("Vault saved successfully.")
		}
	}
}
