package passlib

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
)

var (
	ErrUnsupportedPasswordScheme = errors.New("unsupported password scheme")
	ErrInvalidPasswordFormat     = errors.New("invalid password format")
	ErrUnknownPasswordDigest     = errors.New("unknown password digest")
	ErrInvalidPasswordRounds     = errors.New("invalid password rounds")
	ErrInvalidPasswordSalt       = errors.New("invalid password salt")
)

// VerifyPasswordWithSalt verifies a salted password, against a passlib password hash. This function mimics the
// behaviour of verify_password in flask_security/utils.py
func VerifyPasswordWithSalt(hash string, password string, salt string) (bool, error) {
	h := GetHMAC([]byte(password), []byte(salt))
	return VerifyPassword(hash, []byte(h))
}

// GenPasswordWithSalt generates a passlib password, salted with an app salt string using HMAC. This function generates
// passwords compatible with flask_security.
func GenPasswordWithSalt(password string, salt string) (string, error) {
	// salt clear password with HMAC using app salt string
	h := GetHMAC([]byte(password), []byte(salt))
	// gen 16-byte salt
	rndBytes := make([]byte, 16)
	_, err := rand.Read(rndBytes)
	if err != nil {
		return "", fmt.Errorf("error generating rnd salt: %s", err)
	}
	// return passlib password hash
	return PBKDF2Sha512Password([]byte(h), PasslibAb64Encode(rndBytes), 25000)
}

// GetHMAC returns the HMAC sha512 hash of a password using salt as key. This function mimics the behaviour of get_hmac
// in flask_security/utils.py
func GetHMAC(password []byte, salt []byte) string {
	hf := hmac.New(sha512.New, salt)
	hf.Write(password)
	b := hf.Sum(nil)
	return base64.StdEncoding.EncodeToString(b)
}
