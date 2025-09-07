package util

import (
	"os"
	"strings"
	"testing"
)

func TestGeneratePassword(t *testing.T) {
	// Test with a valid length
	length := 12
	password := GeneratePassword(length)
	if len(password) != length {
		t.Errorf("GeneratePassword returned password of incorrect length: got %d, want %d", len(password), length)
	}

	// Test with an invalid length
	password = GeneratePassword(7)
	if !strings.Contains(password, "Password length must be at least 8 characters") {
		t.Errorf("GeneratePassword with invalid length should have returned an error message, but it didn't")
	}
}

func TestPasswordStrength(t *testing.T) {
	// Test with a strong password
	if !PasswordStrength("aB1!c2D3") {
		t.Error("PasswordStrength with strong password should have returned true, but it didn't")
	}

	// Test with a weak password (missing special character)
	if PasswordStrength("aB1c2D3e") {
		t.Error("PasswordStrength with weak password (missing special character) should have returned false, but it didn't")
	}

	// Test with a weak password (missing digit)
	if PasswordStrength("aBcDeFg!") {
		t.Error("PasswordStrength with weak password (missing digit) should have returned false, but it didn't")
	}

	// Test with a weak password (missing uppercase)
	if PasswordStrength("ab1!c2d3") {
		t.Error("PasswordStrength with weak password (missing uppercase) should have returned false, but it didn't")
	}

	// Test with a weak password (missing lowercase)
	if PasswordStrength("AB1!C2D3") {
		t.Error("PasswordStrength with weak password (missing lowercase) should have returned false, but it didn't")
	}

	// Test with a weak password (too short)
	if PasswordStrength("aB1!c2D") {
		t.Error("PasswordStrength with weak password (too short) should have returned false, but it didn't")
	}
}

func TestEnsureEnvFileExists(t *testing.T) {
	envFileName := ".env"

	// Test when .env file does not exist
	os.Remove(envFileName)
	EnsureEnvFileExists()
	if _, err := os.Stat(envFileName); os.IsNotExist(err) {
		t.Error("EnsureEnvFileExists should have created a .env file, but it didn't")
	}

	// Test when .env file already exists
	content, err := os.ReadFile(envFileName)
	if err != nil {
		t.Fatalf("Failed to read .env file: %v", err)
	}
	EnsureEnvFileExists()
	newContent, err := os.ReadFile(envFileName)
	if err != nil {
		t.Fatalf("Failed to read .env file: %v", err)
	}
	if string(content) != string(newContent) {
		t.Error("EnsureEnvFileExists should not have overwritten an existing .env file")
	}
	os.Remove(envFileName)
}
