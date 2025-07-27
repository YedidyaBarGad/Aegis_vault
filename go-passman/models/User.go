package models

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/joho/godotenv"

	"github.com/YedidyaBarGad/go-passman/crypto"
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

const usersFileEncryptionKeyEnv = "USERS_FILE_ENCRYPTION_KEY"
const localKeyFileName = ".passman_key" // Name of the file where the key will be stored

var usersFileEncryptionKey []byte // Global variable to hold the loaded key

func InitKey() {
	// 1. Try to load .env file first (for development convenience)
	err := godotenv.Load()
	if err != nil {
		log.Printf("INFO: .env file not found or could not be loaded: %v (This is normal if not using a .env file directly)\n", err)
	}

	// 2. Attempt to load key from USERS_FILE_ENCRYPTION_KEY environment variable (highest priority)
	keyStr := os.Getenv(usersFileEncryptionKeyEnv)
	if keyStr != "" {
		var decodeErr error
		usersFileEncryptionKey, decodeErr = base64.StdEncoding.DecodeString(keyStr)
		if decodeErr != nil {
			log.Fatalf("FATAL: Failed to decode Base64 encryption key from environment variable %s: %v", usersFileEncryptionKeyEnv, decodeErr)
		}
		log.Printf("INFO: Encryption key loaded from environment variable %s.\n", usersFileEncryptionKeyEnv)
	} else {
		// 3. If env var not set, try to load from local key file
		executablePath, err := os.Executable()
		if err != nil {
			log.Fatalf("FATAL: Could not get executable path: %v", err)
		}
		localKeyFilePath := filepath.Join(filepath.Dir(executablePath), localKeyFileName)

		keyBytesFromFile, readErr := os.ReadFile(localKeyFilePath)
		if readErr == nil {
			// Key found in local file, use it
			usersFileEncryptionKey = keyBytesFromFile
			log.Printf("INFO: Encryption key loaded from local file: %s.\n", localKeyFilePath)
		} else if os.IsNotExist(readErr) {
			// 4. If neither env var nor local file exists, generate a new key
			log.Printf("INFO: Encryption key not found. Generating a new one...\n")
			newKey, genErr := crypto.GenerateRandomBytes(32) // Generate 32 bytes for AES-256
			if genErr != nil {
				log.Fatalf("FATAL: Failed to generate a new encryption key: %v", genErr)
			}
			usersFileEncryptionKey = newKey

			// 5. Persist the newly generated key to the local file
			writeErr := os.WriteFile(localKeyFilePath, usersFileEncryptionKey, 0600) // Read/write for owner only
			if writeErr != nil {
				log.Fatalf("FATAL: Failed to write new encryption key to file %s: %v", localKeyFilePath, writeErr)
			}
			log.Printf("SUCCESS: New encryption key generated and saved to: %s.\n", localKeyFilePath)

			// **Important Security Note:** When generating and saving a key,
			// it's good practice to provide a warning that this is happening
			// and that this key is critical for data integrity.
			fmt.Printf("\n*** SECURITY ALERT ***\n")
			fmt.Printf("A new encryption key has been generated and saved to: %s\n", localKeyFilePath)
			fmt.Printf("This key is CRITICAL for decrypting your user data and vaults.\n")
			fmt.Printf("If this file is lost or corrupted, your data will be UNRECOVERABLE.\n")
			fmt.Printf("Please back up this file in a secure location: %s\n", localKeyFilePath)
			fmt.Printf("**********************\n\n")

		} else {
			// Other error reading the file
			log.Fatalf("FATAL: Error reading local key file %s: %v", localKeyFilePath, readErr)
		}
	}

	// 6. Validate the final key length
	if len(usersFileEncryptionKey) != 32 {
		log.Fatalf("FATAL: Final encryption key length is %d bytes, but must be 32 bytes for AES-256.", len(usersFileEncryptionKey))
	}
}

// LoadUsers loads the users from the specified file.
// It returns a Users object or an error if the file cannot be read or parsed.
func LoadUsers(filename string) (*Users, error) {
	keyBase64, err := crypto.GetKeyBase64()
	if err != nil {
		return nil, fmt.Errorf("error getting encryption key: %v", err)
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return &Users{Users: []User{}, Number: 0}, nil
		}
		return nil, fmt.Errorf("error reading users file: %v", err)
	}

	var users Users
	decreaptedData, err := crypto.Decrypt(string(data), []byte(keyBase64))
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
	keyBase64, err := crypto.GetKeyBase64()
	if err != nil {
		return fmt.Errorf("error getting encryption key: %v", err)
	}
	encriptedData, err := crypto.Encrypt(data, keyBase64)
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
