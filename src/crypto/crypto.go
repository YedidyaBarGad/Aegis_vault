package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"

	"golang.org/x/crypto/scrypt"
)

// GenerateRandomBytes generates a slice of random bytes of the specified length. Used for nonces and salt.
// It returns an error if the length is less than or equal to zero.
func GenerateRandomBytes(length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("length must be greater than zero")
	}

	bytes := make([]byte, length)
	for i := range bytes {
		// Seed the random number generator with the current time
		rand.New(rand.NewSource((time.Now().UnixNano())))
		// Generate a random byte
		bytes[i] = byte(rand.Intn(256)) // rand.Intn(256) gives a value between 0 and 255
	}
	return bytes, nil
}

// DeriveKey derives a key from the given password and salt using the scrypt algorithm.
// It returns the derived key or an error if the password or salt is empty.
func DeriveKey(password, salt []byte) ([]byte, error) {
	if len(password) == 0 || len(salt) == 0 {
		return nil, fmt.Errorf("password and salt must not be empty")
	}

	// Use scrypt to derive a key from the password and salt
	key, err := scrypt.Key(password, salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %v", err)
	}

	return key, nil
}

// Encrypt encrypts the given data using the provided password.
// It generates a random salt and nonce, derives a key from the password, and returns the encrypted data as a base64 string.
func Encrypt(data, password []byte) ([]byte, error) {
	// Generate a random salt for key derivation
	salt, err := GenerateRandomBytes(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}
	// Generate a random nonce for encryption
	nonce, err := GenerateRandomBytes(12)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Derive a key from the password and salt
	key, err := DeriveKey(password, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %v", err)
	}

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	// Use GCM mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	// Encrypt the data using AES-GCM
	ciphertext := aesGCM.Seal(nil, nonce, data, nil)
	if ciphertext == nil {
		return nil, fmt.Errorf("encryption failed")
	}

	// Seal the data with the derived key and salt and nonce and return the encrypted data as a base64 string
	sealedData := append(salt, nonce...)
	sealedData = append(sealedData, ciphertext...)
	encryptedData := make([]byte, base64.StdEncoding.EncodedLen(len(sealedData)))
	base64.StdEncoding.Encode(encryptedData, sealedData)
	return encryptedData, nil
}

// Decrypt decrypts the given base64 encoded encrypted data using the provided password.
// It returns the decrypted data or an error if decryption fails.
func Decrypt(encryptedData string, password []byte) ([]byte, error) {
	// Decode the base64 encoded encrypted data
	sealedData, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %v", err)
	}

	// Extract salt and nonce from the sealed data
	if len(sealedData) < 28 { // 16 bytes for salt + 12 bytes for nonce
		return nil, fmt.Errorf("invalid sealed data length")
	}
	salt := sealedData[:16]
	nonce := sealedData[16:28]
	ciphertext := sealedData[28:]

	// Derive the key from the password and salt
	key, err := DeriveKey(password, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %v", err)
	}

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	// Use GCM mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	// Decrypt the data using AES-GCM
	data, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %v", err)
	}

	return data, nil
}

func HashContent(content string) string {
	hash := sha256.New()
	hash.Write([]byte(content))
	return hex.EncodeToString(hash.Sum(nil))
}
