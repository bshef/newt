package newt

import (
    "encoding/base64"
	"encoding/json"
    "net/http"
	"strings"
	"time"
	"errors"
)

// Reference: https://github.com/dgrijalva/jwt-go/blob/master/token.go

// KeyFunc defines the type of function which receives a parsed token
// and then returns it for validating.
type KeyFunc func(*Token) (interface{}, error)

// Token defines the data structure representing a Ninja Encrypted Token.
type Token struct {
	Raw       string                 // The raw token. Populated when you Parse a token
	Method    SigningMethod          // The signing method used or to be used
	Header    map[string]interface{} // The first segment of the token
	Claims    map[string]interface{} // The second segment of the token
	Signature string                 // The third segment of the token. Populated when you Parse a token
	Valid     bool                   // Is the token valid? Populated when you Parse/Verify a token
}

// TimeFunc provides the current time when parsing token to validate "exp" claim (expiration time).
var TimeFunc = time.Now

const typ = "NEWT"

// New creates a new Token. Takes a signing method
func New(method SigningMethod) *Token {
	return &Token{
		Header: map[string]interface{}{
			"typ": typ,
			"alg": method.Alg(),
		},
		Claims: make(map[string]interface{}),
		Method: method,
	}
}

// SignedString returns the complete, signed token
func (t *Token) SignedString(key interface{}) (string, error) {
	var sig, sstr string
	var err error
	if sstr, err = t.SigningString(); err != nil {
		return "", err
	}
	if sig, err = t.Method.Sign(sstr, key); err != nil {
		return "", err
	}
	return strings.Join([]string{sstr, sig}, "."), nil
}

// SigningString generates the signing string.
func (t *Token) SigningString() (string, error) {
	var err error
	parts := make([]string, 2)
	for i := range parts {
		var source map[string]interface{}
		if i == 0 {
			source = t.Header
		} else {
			source = t.Claims
		}

		var jsonValue []byte
		if jsonValue, err = json.Marshal(source); err != nil {
			return "", err
		}

		parts[i] = EncodeSegment(jsonValue)
	}
	return strings.Join(parts, "."), nil
}

// Parse parses, validates, and returns a token.
// keyFunc will receive the parsed token and should return the key for validating.
func Parse(tokenString string, keyFunc KeyFunc) (*Token, error) {
	return new(Parser).Parse(tokenString, keyFunc)
}

// ParseFromRequest will try to find the token in an http.Request.
// This method will call ParseMultipartForm if there's no token in the header.
// Currently, it looks in the Authorization header as well as
// looking for an 'access_token' request parameter in req.Form.
func ParseFromRequest(req *http.Request, keyFunc KeyFunc) (token *Token, err error) {
	// Look for an Authorization header
	if ah := req.Header.Get("Authorization"); ah != "" {
		// Should be a bearer token
		if len(ah) > 6 && strings.ToUpper(ah[0:7]) == "BEARER " {
			return Parse(ah[7:], keyFunc)
		}
	}

	// Look for "access_token" parameter
	req.ParseMultipartForm(10e6)
	if tokStr := req.Form.Get("access_token"); tokStr != "" {
		return Parse(tokStr, keyFunc)
	}

	return nil, errors.New("No token in request.")

}

// EncodeSegment encodes specific base64url encoding with padding stripped
func EncodeSegment(seg []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(seg), "=")
}

// DecodeSegment decodes specific base64url encoding with padding stripped
func DecodeSegment(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
}