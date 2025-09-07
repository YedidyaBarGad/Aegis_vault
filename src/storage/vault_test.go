package storage

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/YedidyaBarGad/Aegis_vault/models"
)

func TestSaveLoadVault(t *testing.T) {
	vaultPath := "test_vault.json"
	password := []byte("testpassword")
	creds := []models.Credential{
		{
			Site:     "test.com",
			Username: "testuser",
			Password: "testpassword",
		},
	}

	// Save the vault
	if err := SaveVault(vaultPath, creds, password); err != nil {
		t.Fatalf("SaveVault failed: %v", err)
	}
	defer os.Remove(vaultPath)

	// Load the vault
	loadedCreds, err := LoadVault(vaultPath, password)
	if err != nil {
		t.Fatalf("LoadVault failed: %v", err)
	}

	// Check if the loaded credentials match the original credentials
	if !reflect.DeepEqual(creds, loadedCreds) {
		t.Error("Loaded credentials do not match original credentials")
	}

	// Test with incorrect password
	_, err = LoadVault(vaultPath, []byte("wrongpassword"))
	if err == nil {
		t.Error("LoadVault with incorrect password should have failed, but it didn't")
	}
}

func TestFileExists(t *testing.T) {
	// Test with an existing file
	filePath := "test_file.txt"
	if _, err := os.Create(filePath); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	defer os.Remove(filePath)
	if !FileExists(filePath) {
		t.Error("FileExists with existing file should have returned true, but it didn't")
	}

	// Test with a non-existent file
	if FileExists("nonexistent_file.txt") {
		t.Error("FileExists with non-existent file should have returned false, but it didn't")
	}
}

func TestDeleteVault(t *testing.T) {
	// Create a test vault file
	vaultPath := "test_vault_to_delete.json"
	if _, err := os.Create(vaultPath); err != nil {
		t.Fatalf("Failed to create test vault file: %v", err)
	}

	// Delete the vault file
	if err := DeleteVault(vaultPath); err != nil {
		t.Fatalf("DeleteVault failed: %v", err)
	}

	// Check if the file still exists
	if FileExists(vaultPath) {
		t.Error("DeleteVault should have deleted the vault file, but it still exists")
	}

	// Test deleting a non-existent vault file
	if err := DeleteVault("nonexistent_vault.json"); err == nil {
		t.Error("DeleteVault with non-existent vault file should have failed, but it didn't")
	}
}

func TestGetVaultPath(t *testing.T) {
	username := "testuser"
	vaultDir := "test_vaults"
	expectedPath := filepath.Join(vaultDir, "ae5deb822e_vault.json")
	if path := GetVaultPath(username, vaultDir); path != expectedPath {
		t.Errorf("GetVaultPath returned incorrect path: got %s, want %s", path, expectedPath)
	}
}
