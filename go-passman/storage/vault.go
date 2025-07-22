package storage

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/YedidyaBarGad/go-passman/crypto"
	"github.com/YedidyaBarGad/go-passman/models"
)

// Serializes credentials to JSON, encrypts them with the master password, and writes to the vault file: vault.json.
// It returns an error if serialization, encryption, or file operations fail.
func SaveVault(path string, creds []models.Credential, password []byte) error {
	// Serialize credentials to JSON
	data, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("failed to serialize credentials: %v", err)
	}

	// Encrypt the serialized data
	encryptedData, err := crypto.Encrypt(data, password)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %v", err)
	}

	// Write the encrypted data to the vault file
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create vault file: %v", err)
	}
	defer file.Close()

	if _, err := file.WriteString(encryptedData); err != nil {
		return fmt.Errorf("failed to write to vault file: %v", err)
	}

	return nil
}

// LoadVault reads the vault file, decrypts the data using the master password, and returns the credentials.
func LoadVault(path string, password []byte) ([]models.Credential, error) {
	// Turn the os.File into a string in order to decrypt it
	if !FileExists(path) {
		return nil, fmt.Errorf("vault file does not exist at path: %s", path)
	}

	// Read the vault file
	fileContent, err := os.ReadFile(path)
	if err != nil {
		return []models.Credential{}, fmt.Errorf("failed to read vault file: %v", err)
	}

	dataStr := string(fileContent)
	// Check if the file is empty
	if len(dataStr) == 0 {
		return []models.Credential{}, fmt.Errorf("vault file is empty")
	}
	// Decrypt the data using the master password
	fileDecrypt, err := crypto.Decrypt(dataStr, password)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %v", err)
	}
	// Deserialize the JSON data into credentials
	var creds []models.Credential
	if err := json.Unmarshal([]byte(fileDecrypt), &creds); err != nil {
		return nil, fmt.Errorf("failed to deserialize credentials: %v", err)
	}
	// Validate each credential
	for _, cred := range creds {
		if err := models.ValidateCredential(cred); err != nil {
			return nil, fmt.Errorf("invalid credential: %v", err)
		}
	}
	return creds, nil
}

func FileExists(path string) bool {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil || os.IsExist(err)
}

// DeleteVault deletes the vault file at the specified path.
func DeleteVault(path string) error {
	if !FileExists(path) {
		return fmt.Errorf("vault file does not exist at path: %s", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("failed to delete vault file: %v", err)
	}
	return nil
}
