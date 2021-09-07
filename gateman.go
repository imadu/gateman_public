package gatemanpublic

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/mergermarket/go-pkcs7"
)

const macFormatVersion = "2"
const macPrefix = "Ko004." + macFormatVersion
const passwordId = ""
const delimiter = "*"

//Gateman struct is the structure that holds the gateman fields
type Gateman struct {
	// Name of the service initializing Gateman
	service string

	// redis is a Redis client representing a pool of zero or more underlying connections.
	// It's safe for concurrent use by multiple goroutines.
	redis *redis.Client

	// Auth scheme used for headless inter-service calls
	authScheme string

	// Secret key for sealing & unsealing objects
	secret string

	// Default duration period used for persisting tokens. Defaults to `600` seconds (10 minutes)
	sessionDuration time.Duration
}

// NewGateman creates a new gateman client
func NewGateman(
	service string,
	redis *redis.Client,
	authScheme string,
	secret string,
	sessionDuration time.Duration,
) (*Gateman, error) {
	if service == "" {
		return nil, errors.New("gateman: empty service name")
	}

	if redis == nil {
		return nil, errors.New("gateman: empty redis store(client) provided")
	}

	if authScheme == "" {
		return nil, errors.New("gateman: empty auth scheme")
	}

	if secret == "" {
		return nil, errors.New("gateman: empty secret")
	}

	if len([]byte(secret)) < aes.BlockSize {
		return nil, errors.New("gateman: secret string too short. (min 32 characters required)")
	}

	if sessionDuration == 0 {
		sessionDuration = 10 * time.Minute
	}

	gateman := &Gateman{
		service, redis, authScheme, secret, sessionDuration,
	}

	return gateman, nil
}

// encrypt encrypts data using AES-256
//
// It returns the encrypted payload and the key
func (g *Gateman) encrypt(payload []byte) (encrypted []byte, keyResult *KeyResult, err error) {
	keyResult, err = generateEncryptionKey(g.secret)

	if err != nil {
		return nil, nil, err
	}

	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block
	payload, err = pkcs7.Pad(payload, aes.BlockSize)

	if err != nil {
		// Review content of error message returned to prevent padding oracle attacks
		// For context, see https://en.wikipedia.org/wiki/Padding_oracle_attack
		return nil, nil, fmt.Errorf(`gateman: payload "%s" has error`, payload)
	}

	if len(payload)%aes.BlockSize != 0 {
		// Review content of error message returned to prevent padding oracle attacks
		// For context, see https://en.wikipedia.org/wiki/Padding_oracle_attack
		return nil, nil, errors.New("gateman: couldn't seal object")
	}

	block, err := aes.NewCipher(keyResult.key)

	if err != nil {
		return nil, nil, err
	}

	cipherText := make([]byte, len(payload))

	mode := cipher.NewCBCEncrypter(block, keyResult.iv)

	mode.CryptBlocks(cipherText, payload)

	return cipherText, keyResult, nil
}

// hmac authenticates a message and returns a SHA256 HMAC
//
// It allows us sign and verify the integrity of messages
func (g *Gateman) hmac(message string) (result []byte, hmacKey *KeyResult, err error) {
	keyResult, err := generateHMACKey(g.secret)

	if err != nil {
		return nil, nil, err
	}

	h := hmac.New(sha256.New, keyResult.key)

	_, err = h.Write([]byte(message))

	if err != nil {
		return nil, nil, err
	}

	result = h.Sum(nil)

	return result, keyResult, nil
}

// hmac authenticates a message using a provided key and returns a SHA256 HMAC
//
// It allows us sign and verify the integrity of messages
func (g *Gateman) hmacWithKey(message string, key []byte) (result []byte, err error) {
	h := hmac.New(sha256.New, key)

	_, err = h.Write([]byte(message))

	if err != nil {
		return nil, err
	}

	result = h.Sum(nil)

	return result, nil
}

// Seal generates a url-safe token by encrypting and hmac-ing a JSON object (struct with JSON tags)
// It seals an object using symmetric key encryption (AES-256) with message integrity verification (SHA256).
// The seal process/flow is modelled after the Iron Node.js library https://hapi.dev/module/iron/
// When the `ttl` is provided, a timestamp is attached to the token
func (g *Gateman) Seal(payload GatemanPayload, ttl time.Duration) (token string, err error) {
	jsonPayload, err := json.Marshal(payload)

	if err != nil {
		return "", errors.New("gateman: json marshal error")
	}

	rawCipherText, encryptionParts, err := g.encrypt(jsonPayload)

	if err != nil {
		return "", err
	}

	// set the token's ttl if applicable
	expiration := ""

	if ttl != 0 {
		// convert to milliseconds
		duration := time.Now().Add(ttl).UnixNano() / 1e6
		expiration = strconv.FormatInt(duration, 10)
	}

	encryptionIV := base64.RawURLEncoding.EncodeToString(encryptionParts.iv)
	cipherText := base64.RawURLEncoding.EncodeToString(rawCipherText)
	encryptionSalt := string(encryptionParts.salt)

	macBaseString := macPrefix + delimiter + passwordId +
		delimiter + encryptionSalt + delimiter + encryptionIV +
		delimiter + cipherText + delimiter + expiration

	rawHmac, hmacParts, err := g.hmac(macBaseString)

	if err != nil {
		return "", nil
	}

	encodedHmac := base64.RawURLEncoding.EncodeToString(rawHmac)

	hmacSalt := string(hmacParts.salt)

	token = macBaseString + delimiter + hmacSalt + delimiter + encodedHmac

	return token, nil
}

// Unseal decrypts an encrypted token and returns the underlying payload
// It unseals an object using symmetric key encryption (AES-256) with message integrity verification (SHA256).
// The unseal process/flow is modelled after the Iron Node.js library https://hapi.dev/module/iron/
// The JSON payload contained in the token is unmarshalled into the provided `dst` pointer, which should
// be a struct with (recognised) json tags
func (g *Gateman) Unseal(token string, dst interface{}) (err error) {
	parts := strings.Split(token, delimiter)

	if len(parts) != 8 {
		return errors.New("gateman: incorrect number of sealed components")
	}

	macPrefix := parts[0]
	passwordId := parts[1]
	encryptionSalt := parts[2]
	encryptionIVBase64 := parts[3]
	cipherTextBase64 := parts[4]
	expiration := parts[5]
	hmacSalt := parts[6]
	hmacBase64 := parts[7]

	macBaseString := macPrefix + delimiter + passwordId +
		delimiter + encryptionSalt + delimiter + encryptionIVBase64 +
		delimiter + cipherTextBase64 + delimiter + expiration

	// TODO: Validate TTL for headless tokens and mac prefix

	// validate HMAC
	// it's critical to note that ciphertexts must be authenticated (i.e. by
	// using crypto/hmac) before being decrypted in order to avoid creating
	// a padding oracle.
	hmacKey := generateHMACKeyWithSalt(g.secret, hmacSalt)

	computedHmac, err := g.hmacWithKey(macBaseString, hmacKey)

	if err != nil {
		return err
	}

	computedHmacBase64 := base64.RawURLEncoding.EncodeToString(computedHmac)

	if !hmac.Equal([]byte(hmacBase64), []byte(computedHmacBase64)) {
		return errors.New("gateman: bad hmac value")
	}

	// Decrypt token
	encryptionKey := generateEncryptionKeyWithSalt(g.secret, encryptionSalt)

	block, err := aes.NewCipher(encryptionKey)

	if err != nil {
		return err
	}

	encryptionIV, err := base64.RawURLEncoding.DecodeString(encryptionIVBase64)

	if err != nil {
		return err
	}

	rawCipherText, err := base64.RawURLEncoding.DecodeString(cipherTextBase64)

	if err != nil {
		return err
	}

	if len(rawCipherText) < aes.BlockSize {
		panic("ciphertext too short")
	}

	// CBC mode always works in whole blocks.
	if len(rawCipherText)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, encryptionIV)

	payload := rawCipherText

	mode.CryptBlocks(payload, payload)

	// If the original plaintext lengths are not a multiple of the block
	// size, padding would have to be added when encrypting, which would be
	// removed at this point.
	payload, err = pkcs7.Unpad(payload, aes.BlockSize)

	if err != nil {
		return err
	}

	// convert payload to JSON
	err = json.Unmarshal(payload, dst)

	if err != nil {
		return err
	}

	return nil
}

// CreateSession creates an encrypted token using the user's id and role
// The token is persisted to Redis for a specified duration.
// Used for creating `admin` and `user` sessions
func (g *Gateman) CreateSession(
	id string,
	role string,
	data interface{},
) (string, error) {
	payload := GatemanPayload{
		Id:      id,
		Role:    role,
		Data:    data,
		Service: g.service,
	}

	token, err := g.Seal(payload, 0)

	if err != nil {
		return "", err
	}

	// persist token to redis
	err = g.redis.Set(context.TODO(), payload.Id, token, g.sessionDuration).Err()

	if err != nil {
		return "", err
	}

	return token, nil
}

// CreateHeadlessToken creates an encrypted headless token which expires after a minute
func (g *Gateman) CreateHeadlessToken(
	id string,
	data interface{},
) (string, error) {
	payload := GatemanPayload{
		Id:      id,
		Role:    "service",
		Data:    data,
		Service: g.service,
	}

	// headless tokens are not persisted to redis, instead we specify a ttl of
	// 1 minute on the token. 1 minute was chosen because headless tokens are intended for
	// internal calls between services, which typically shouldn't take too long.
	// it's also assumed that headless tokens are not reusable, hence the 1-minute ttl
	token, err := g.Seal(payload, time.Second*60)

	if err != nil {
		return "", err
	}

	return token, nil
}

//Guard func to guard
func (g *Gateman) Guard(roles []string, services []string) func(handler http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		middleware := func(w http.ResponseWriter, r *http.Request) {
			headerScheme, token, err := ValidateAuthHeader(g.authScheme, r)

			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			dataInterface := GatemanPayload{}

			// Handle token decryption and validation
			err = g.Unseal(token, &dataInterface)

			if err != nil {

				errorMessage := fmt.Errorf("could not unseal token: %v", err)
				http.Error(w, errorMessage.Error(), http.StatusUnauthorized)

				return
			}

			validateOptions := ValidateRoleOptions{
				ServiceAuthScheme: g.authScheme,
				Role:              roles,
				Service:           services,
				Scheme:            headerScheme,
				Data:              dataInterface,
			}

			err = ValidateOptions(validateOptions)
			if err != nil {

				errorMessage := fmt.Errorf("could not validate options: %v", err)
				http.Error(w, errorMessage.Error(), http.StatusUnauthorized)
				return
			}

			if headerScheme == "Bearer" {
				sessionToken := g.redis.Get(r.Context(), dataInterface.Id)

				if sessionToken == nil {
					errorMessage := fmt.Errorf("invalid session token: %v", sessionToken)
					http.Error(w, errorMessage.Error(), http.StatusUnauthorized)
					return
				}

				if sessionToken.Val() != token {
					errorMessage := fmt.Errorf("invalid session token")
					http.Error(w, errorMessage.Error(), http.StatusUnauthorized)

					return
				}
			}

			userObject := map[string]interface{}{}
			userObject["id"] = dataInterface.Id
			userObject["data"] = dataInterface.Data

			// Attach decoded data to request context and invoke the next handler in the chain
			// create a new context with the user object
			ctx := context.WithValue(r.Context(), "user", userObject)
			next.ServeHTTP(w, r.WithContext(ctx))
		}

		// Wrap the middleware function and convert it to a http handler via type-conversion
		return http.HandlerFunc(
			middleware,
		)
	}
}
