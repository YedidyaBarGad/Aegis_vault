package crypto

import (
	"bytes"
	"testing"
)

func TestGenerateRandomBytes(t *testing.T) {
	// Test with a valid length
	length := 16
	bytes, err := GenerateRandomBytes(length)
	if err != nil {
		t.Errorf("GenerateRandomBytes with valid length failed: %v", err)
	}
	if len(bytes) != length {
		t.Errorf("GenerateRandomBytes returned bytes of incorrect length: got %d, want %d", len(bytes), length)
	}

	// Test with an invalid length
	_, err = GenerateRandomBytes(0)
	if err == nil {
		t.Error("GenerateRandomBytes with invalid length should have failed, but it didn't")
	}
}

func TestDeriveKey(t *testing.T) {
	password := []byte("testpassword")
	salt := []byte("testsalt")

	// Test with valid inputs
	key, err := DeriveKey(password, salt)
	if err != nil {
		t.Errorf("DeriveKey with valid inputs failed: %v", err)
	}
	if len(key) == 0 {
		t.Error("DeriveKey returned an empty key")
	}

	// Test with empty password
	_, err = DeriveKey([]byte{}, salt)
	if err == nil {
		t.Error("DeriveKey with empty password should have failed, but it didn't")
	}

	// Test with empty salt
	_, err = DeriveKey(password, []byte{})
	if err == nil {
		t.Error("DeriveKey with empty salt should have failed, but it didn't")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	data := []byte("testdata")
	password := []byte("testpassword")

	// Encrypt the data
	encryptedData, err := Encrypt(data, password)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt the data
	decryptedData, err := Decrypt(string(encryptedData), password)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Check if the decrypted data matches the original data
	if !bytes.Equal(data, decryptedData) {
		t.Error("Decrypted data does not match original data")
	}

	// Test with incorrect password
	_, err = Decrypt(string(encryptedData), []byte("wrongpassword"))
	if err == nil {
		t.Error("Decrypt with incorrect password should have failed, but it didn't")
	}
}

func TestHashContent(t *testing.T) {
	content := "testcontent"
	hash1 := HashContent(content)
	hash2 := HashContent(content)

	if hash1 != hash2 {
		t.Error("HashContent should produce the same hash for the same content")
	}

	differentContent := "differentcontent"
	hash3 := HashContent(differentContent)
	if hash1 == hash3 {
		t.Error("HashContent should produce different hashes for different content")
	}
}
