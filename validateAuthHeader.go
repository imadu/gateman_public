package gatemanpublic

import (
	"errors"
	"net/http"
	"strings"
)

//ReturnedData used for returning the scheme and token from the header

//ValidateAuthHeader used to validate the token and scheme coming from the request
func ValidateAuthHeader(gatemanScheme string, r *http.Request) (headerScheme string, token string, err error) {
	authorizationHeader := r.Header.Get("Authorization")

	if authorizationHeader == "" {
		return "", "", errors.New("required authorization header not found")
	}

	headerParts := strings.Split(authorizationHeader, " ")

	headerScheme = headerParts[0]
	token = headerParts[1]

	if token == "" {
		return "", "", errors.New("token not specified in authorization header")
	}

	// Check if the scheme found in the authorization header is a recognized
	// scheme. Valid schemes are the Bearer scheme and the scheme provided to the
	// gateman constructor
	if headerScheme == "Bearer" || headerScheme == gatemanScheme {
		return headerScheme, token, nil
	}

	return "", "", errors.New("invalid auth scheme provided")
}
