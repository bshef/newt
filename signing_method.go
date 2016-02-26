package newt

var signingMethods = map[string]func() SigningMethod{}

// SigningMethod defines the type of signing used on the token.
// Implement SigningMethod to add new methods for signing or verifying tokens.
type SigningMethod interface {
    Verify(signingString, signature string, key interface{}) error // Returns nil if signature is valid
	Sign(signingString string, key interface{}) (string, error)    // Returns encoded signature or error
	Alg() string                                                   // Returns the alg identifier for this method (example: 'AES128')
}

// RegisterSigningMethod registers the "alg" name and a factory function for signing method.
// This is typically done during init() in the method's implementation
func RegisterSigningMethod(alg string, f func() SigningMethod) {
	signingMethods[alg] = f
}

// GetSigningMethod gets a signing method from an "alg" string
func GetSigningMethod(alg string) (method SigningMethod) {
	if methodF, ok := signingMethods[alg]; ok {
		method = methodF()
	}
	return
}