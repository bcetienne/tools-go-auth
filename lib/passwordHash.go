package lib

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

type PasswordHash struct {
}

type PasswordHashInterface interface {
	Hash(password string) (string, error)
	CheckHash(password, hash string) bool
}

func NewPasswordHash() PasswordHash {
	return PasswordHash{}
}

func (ph *PasswordHash) Hash(password string) (string, error) {
	if len(password) == 0 {
		return "", fmt.Errorf("empty password")
	}
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func (ph *PasswordHash) CheckHash(password, hash string) bool {
	if len(password) == 0 || len(hash) == 0 {
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil // Return true when no errors
}
