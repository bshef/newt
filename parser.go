package newt

import (
    "errors"
    log "github.com/Sirupsen/logrus"
	"strings"
	"encoding/json"
	"bytes"
	"fmt"
)

//  Reference: https://github.com/dgrijalva/jwt-go/blob/master/parser.go

// Parser defines configuration values for the Parser instance.
type Parser struct {
	ValidMethods  []string // If populated, only these methods will be considered valid
	UseJSONNumber bool     // Use JSON Number format in JSON decoder
}

const delimiter                 = "."

const methodHeader              = "alg"
const bearerHeader              = "bearer"
const claimsExpiration          = "exp"
const claimsNotBefore           = "nbf"

// Parse parses, validates, and returns a token (or error, if one arises).
// keyFunc will receive the parsed token and should return the key for validating.
func (p *Parser) Parse(tokenString string, keyFunc KeyFunc) (*Token, error) {
    parts := strings.Split(tokenString, delimiter)
	if len(parts) != 3 {
		return nil, errors.New(invalidNumSegmentsErr)
	}
    
    log.WithFields(log.Fields {
        "segments": parts,
    }).Debug("Segments identified.")

	var err error
	token := &Token{Raw: tokenString}
    
	// Parse Header
	var headerBytes []byte
	if headerBytes, err = DecodeSegment(parts[0]); err != nil {
		if strings.HasPrefix(strings.ToLower(tokenString), bearerHeader) {
			return token, errors.New(containsBearerErr)
		}
		return token, errors.New(malformedErr)
	}
	if err = json.Unmarshal(headerBytes, &token.Header); err != nil {
		return token, errors.New(malformedErr)
	}

	// Parse Claims
	var claimBytes []byte
	if claimBytes, err = DecodeSegment(parts[1]); err != nil {
		return token, errors.New(malformedErr)
	}
	dec := json.NewDecoder(bytes.NewBuffer(claimBytes))
	if p.UseJSONNumber {
		dec.UseNumber()
	}
	if err = dec.Decode(&token.Claims); err != nil {
		return token, errors.New(malformedErr)
	}

	// Lookup signature method
	if method, ok := token.Header[methodHeader].(string); ok {
		if token.Method = GetSigningMethod(method); token.Method == nil {
			return token, errors.New(signingMethodUnavailErr)
		}
	} else {
		return token, errors.New(signingMethodUnspecErr)
	}

	// Verify signing method is in the required set
	if p.ValidMethods != nil {
		var signingMethodValid = false
		var alg = token.Method.Alg()
		for _, m := range p.ValidMethods {
			if m == alg {
				signingMethodValid = true
				break
			}
		}
		if !signingMethodValid {
			// signing method is not in the listed set            
			return token, fmt.Errorf(signingMethodInvalidErr, alg)
		}
	}

	// Lookup key
	var key interface{}
	if keyFunc == nil {
		// keyFunc was not provided.  short circuiting validation
		return token, errors.New(noKeyFuncErr)
	}
	if key, err = keyFunc(token); err != nil {
		// keyFunc returned an error
		return token, err
	}

	// Check expiration times
	now := TimeFunc().Unix()
	if exp, ok := token.Claims[claimsExpiration].(float64); ok {
		if now > int64(exp) {
			return token, errors.New(tokenExpErr)
		}
	}
	if nbf, ok := token.Claims[claimsNotBefore].(float64); ok {
		if now < int64(nbf) {
			return token, errors.New(futureTokenErr)
		}
	}

	// Perform validation
	token.Signature = parts[2]
	if err = token.Method.Verify(strings.Join(parts[0:2], delimiter), token.Signature, key); err != nil {
		return token, errors.New(invalidSignatureErr)
	}

	token.Valid = true
    return token, nil
}