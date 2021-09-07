package gatemanpublic

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"

	"github.com/xdg-go/pbkdf2"
)

const (
	SALT_BITS    = 256
	KEY_BITS     = 256
	IV_BITS      = 128
	HMAC_IV_BITS = 256
	ITERATIONS   = 1
)

type KeyResult struct {
	key  []byte
	salt []byte
	iv   []byte
}

// generateEncryptionKey generates a unique 32-byte encryption key using the
// PBKDF2 derivation function.
//
// It uses a pseudorandom function to derive a secure encryption key that can be used
// with AES-256 (which needs a 32-byte key)
//
// It returns the derived key, the random salt used and an initialization vector (IV).
func generateEncryptionKey(password string) (*KeyResult, error) {
	salt := make([]byte, SALT_BITS/8)

	_, err := io.ReadFull(rand.Reader, salt)

	if err != nil {
		return nil, errors.New("gateman: failed to generate key salt")
	}

	// The Node.js Iron library encodes the 32-byte salt to a hex string for some reason
	// This causes the number of bytes in the string encoding to double, effectively
	// generating a 64-byte salt string which we use to generate the key
	// See: https://github.com/hapijs/iron/blob/66a28dbfe82aa717beaf35e76cd30187dd59668e/lib/index.js#L104
	saltHex := hex.EncodeToString(salt)

	key := pbkdf2.Key([]byte(password), []byte(saltHex), ITERATIONS, KEY_BITS/8, sha1.New)

	iv := make([]byte, IV_BITS/8)

	_, err = io.ReadFull(rand.Reader, iv)

	if err != nil {
		return nil, errors.New("gateman: failed to generate iv")
	}

	result := &KeyResult{key: key, salt: []byte(saltHex), iv: iv}

	return result, nil
}

// generateEncryptionKeyWithSalt generates a 32-byte decryption key using the
// PBKDF2 derivation function.
//
// It uses the provided salt to generate the key
func generateEncryptionKeyWithSalt(password string, salt string) []byte {
	key := pbkdf2.Key([]byte(password), []byte(salt), ITERATIONS, KEY_BITS/8, sha1.New)
	return key
}

// generateHMACKey generates a unique 32-byte HMAC key using the
// PBKDF2 derivation function.
//
// It uses a pseudorandom function to derive a secure encryption key that can be used
// with SHA256 (which needs a 32-byte key)
//
// It returns the derived key and the random salt used.
func generateHMACKey(password string) (*KeyResult, error) {
	salt := make([]byte, SALT_BITS/8)

	_, err := io.ReadFull(rand.Reader, salt)

	if err != nil {
		return nil, errors.New("gateman: failed to generate key salt")
	}

	// The Node.js Iron library encodes the 32-byte salt to a hex string for some reason
	// This causes the number of bytes in the string encoding to double, effectively
	// generating a 64-byte salt string which we use to generate the key
	// See: https://github.com/hapijs/iron/blob/66a28dbfe82aa717beaf35e76cd30187dd59668e/lib/index.js#L104
	saltHex := hex.EncodeToString(salt)

	key := pbkdf2.Key([]byte(password), []byte(saltHex), ITERATIONS, KEY_BITS/8, sha1.New)

	// sha256 doesn't need an IV so it is set to nil
	result := &KeyResult{key: key, salt: []byte(saltHex), iv: nil}

	return result, nil
}

// generateHMACKeyUsingParts generates a 32-byte HMAC key using a provided salt
func generateHMACKeyWithSalt(password string, salt string) []byte {
	key := pbkdf2.Key([]byte(password), []byte(salt), ITERATIONS, KEY_BITS/8, sha1.New)
	return key
}
