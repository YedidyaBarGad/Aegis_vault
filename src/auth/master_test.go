package auth

import (
	"os"
	"testing"

	"github.com/YedidyaBarGad/Aegis_vault/models"
	"github.com/YedidyaBarGad/Aegis_vault/storage"
	"golang.org/x/crypto/bcrypt"
)

func TestVerifyMasterPassword(t *testing.T) {
	// Create a temporary vault file for testing
	vaultPath := "test_vault.json"
	password := []byte("testpassword")
	creds := []models.Credential{
		{
			Site:     "test.com",
			Username: "testuser",
			Password: "testpassword",
		},
	}

	// Save the vault with the test data
	if err := storage.SaveVault(vaultPath, creds, password); err != nil {
		t.Fatalf("Failed to save vault: %v", err)
	}
	defer os.Remove(vaultPath)

	// Test with the correct password
	if err := VerifyMasterPassword(vaultPath, password); err != nil {
		t.Errorf("VerifyMasterPassword with correct password failed: %v", err)
	}

	// Test with an incorrect password
	if err := VerifyMasterPassword(vaultPath, []byte("wrongpassword")); err == nil {
		t.Error("VerifyMasterPassword with incorrect password should have failed, but it didn't")
	}

	// Test with a non-existent vault file
	if err := VerifyMasterPassword("nonexistent_vault.json", password); err == nil {
		t.Error("VerifyMasterPassword with non-existent vault file should have failed, but it didn't")
	}
}

func TestAuthenticateUser(t *testing.T) {
	// Create a test user
	password := "testpassword"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	user := models.User{
		Username: "testuser",
		Password: string(hashedPassword),
	}
	users := &models.Users{
		Users: []models.User{user},
	}

	// Test with a valid username and password
	if !AuthenticateUser("testuser", "testpassword", users) {
		t.Error("AuthenticateUser with valid credentials failed")
	}

	// Test with a valid username and an invalid password
	if AuthenticateUser("testuser", "wrongpassword", users) {
		t.Error("AuthenticateUser with invalid password should have failed, but it didn't")
	}

	// Test with an invalid username
	if AuthenticateUser("nonexistentuser", "testpassword", users) {
		t.Error("AuthenticateUser with invalid username should have failed, but it didn't")
	}
}
