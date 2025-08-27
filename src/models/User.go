package models

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/YedidyaBarGad/Aegis_vault/crypto"
)

// User represents a user in the system.
type User struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	VaultFileName string `json:"vault_file_name"`
}

// Users represents a collection of User objects.
type Users struct {
	Users  []User `json:"users"`
	Number int    `json:"number"`
}

// LoadUsers loads the users from the specified file.
// It returns a Users object or an error if the file cannot be read or parsed.
func LoadUsers(filename string) (*Users, error) {
	key := os.Getenv("USERS_FILE_ENCRYPTION_KEY")
	if key == "" {
		return nil, fmt.Errorf("FATAL: Environment variable USERS_FILE_ENCRYPTION_KEY not set")
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return &Users{Users: []User{}, Number: 0}, nil
		}
		return nil, fmt.Errorf("error reading users file: %v", err)
	}

	//
	var users Users
	decreaptedData, err := crypto.Decrypt(string(data), []byte(key))
	if err != nil {
		return nil, fmt.Errorf("error decrypting users data: %v", err)
	}
	err = json.Unmarshal(decreaptedData, &users)
	if err != nil {
		return nil, err
	}

	return &users, nil
}

// SaveUsers saves the users to the specified file.
// It returns an error if the file cannot be written.
func SaveUsers(filename string, users *Users) error {
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling users data: %v", err)
	}
	// Encrypt the data before saving
	key := os.Getenv("USERS_FILE_ENCRYPTION_KEY")
	if key == "" {
		return fmt.Errorf("FATAL: Environment variable USERS_FILE_ENCRYPTION_KEY not set")
	}
	encriptedData, err := crypto.Encrypt(data, []byte(key))
	if err != nil {
		return fmt.Errorf("error encrypting users data: %v", err)
	}
	err = os.WriteFile(filename, encriptedData, 0644)
	if err != nil {
		return fmt.Errorf("error writing users file: %v", err)
	}
	return nil
}

// FindUser searches for a user by username and returns the User object if found, or nil if not found.
// It returns an error if there is an issue loading the users file.
func FindUser(username string, allUsers *Users) (*User, error) {
	if username == "" || allUsers.Users == nil {
		return nil, fmt.Errorf("users data is not loaded")
	}
	for _, user := range allUsers.Users {
		if strings.EqualFold(user.Username, username) {
			return &user, nil
		}
	}
	return nil, nil
}

// AddUser adds a new user to the users list and saves it to the file.
// It returns an error if the user already exists or if there is an issue saving the file
func AddUser(username, password, vaultFileName, path string, users *Users) error {
	// Check if the user already exists
	if _, err := FindUser(username, users); err != nil {
		return fmt.Errorf("error checking for existing user: %v", err)
	}

	// Add the new user
	newUser := User{
		Username:      username,
		Password:      password,
		VaultFileName: vaultFileName,
	}
	users.Users = append(users.Users, newUser)
	users.Number++

	return SaveUsers(path, users)
}
