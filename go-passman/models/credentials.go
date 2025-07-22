package models

import (
	"fmt"
)

// Credential represents a user's credential with a username and password.
type Credential struct {
	Site     string
	Username string
	Password string
}

// ValidateCredential checks if the given credential is valid.
func ValidateCredential(c Credential) error {
	if c.Site == "" {
		return fmt.Errorf("site cannot be empty")
	}
	if c.Username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	if c.Password == "" {
		return fmt.Errorf("password cannot be empty")
	}
	return nil
}

func FindCredential(creds []Credential, site string) *Credential {
	for _, cred := range creds {
		if cred.Site == site {
			return &cred
		}
	}
	return nil
}

func DeleteCredential(creds []Credential, site string) ([]Credential, bool) {
	for i, cred := range creds {
		if cred.Site == site {
			return append(creds[:i], creds[i+1:]...), true
		}
	}
	return creds, false
}
