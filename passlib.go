package passlib

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const passlibAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./"

// PasslibAb64Encode encodes using a variant of base64, like Passlib.
//
// Check https://pythonhosted.org/passlib/lib/passlib.utils.html#passlib.utils.ab64_encode
var passlibEncoding = base64.NewEncoding(passlibAlphabet).WithPadding(base64.NoPadding)

func PasslibAb64Encode(data []byte) string {
	return passlibEncoding.EncodeToString(data)
}

// PasslibAb64Decode decodes using a variant of base64, like Passlib.
//
// Check https://pythonhosted.org/passlib/lib/passlib.utils.html#passlib.utils.ab64_decode
func PasslibAb64Decode(data string) ([]byte, error) {
	return passlibEncoding.DecodeString(data)
}

// VerifyPassword verifies a passlib generated password, specifically a pbkdf2 hash password, according to the
// rules described in https://pythonhosted.org/passlib/lib/passlib.hash.pbkdf2_digest.html
func VerifyPassword(phash string, pass []byte) (bool, error) {
	// only pbkdf2 supported
	if !strings.HasPrefix(phash, "$pbkdf2-") {
		return false, ErrUnsupportedPasswordScheme
	}

	// five fields expected: $pbkdf2-digest$rounds$salt$checksum
	fields := strings.Split(phash, "$")
	if len(fields) != 5 {
		return false, ErrInvalidPasswordFormat
	}

	// extract digest
	hdr := strings.Split(fields[1], "-")
	if len(hdr) != 2 {
		return false, ErrInvalidPasswordFormat
	}
	var keyLen int
	var hashFunc func() hash.Hash
	switch hdr[1] {
	case "sha256":
		keyLen = sha256.Size
		hashFunc = sha256.New
	case "sha512":
		keyLen = sha512.Size
		hashFunc = sha512.New
	default:
		return false, ErrUnknownPasswordDigest
	}

	// get remaining fields
	rounds, err := strconv.Atoi(fields[2])
	if err != nil {
		return false, ErrInvalidPasswordRounds
	}
	salt, err := PasslibAb64Decode(fields[3])
	if err != nil {
		return false, ErrInvalidPasswordSalt
	}

	k := pbkdf2.Key(pass, salt, rounds, keyLen, hashFunc)
	return fields[4] == PasslibAb64Encode(k), nil
}

// PBKDF2Sha512Password generates a passlib password, specifically a pbkdf2-sha512 password, according to the rules
// described in https://pythonhosted.org/passlib/lib/passlib.hash.pbkdf2_digest.html
func PBKDF2Sha512Password(pass []byte, saltB64 string, rounds int) (string, error) {
	salt, saltErr := PasslibAb64Decode(saltB64)
	if saltErr != nil {
		return "", saltErr
	}
	k := pbkdf2.Key(pass, salt, rounds, sha512.Size, sha512.New)
	phash := "$pbkdf2-sha512$" + strconv.Itoa(rounds) + "$" + saltB64 + "$" + PasslibAb64Encode(k)
	return phash, nil
}
