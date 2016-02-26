package newt

import (
    "crypto/aes"
    "crypto/cipher"
)

// SigningMethodAES implements the AES family of signing methods
type SigningMethodAES struct {
    Name string   
}

// Specific instances for AES-128 (Rijndael) and any additional AES flavors.
var (
    SigningMethodAES128 *SigningMethodAES
)

func init() {
    // AES-128 (Rijndael)
    SigningMethodAES128 = &SigningMethodAES{"AES128"}
    RegisterSigningMethod(SigningMethodAES128.Alg(), func() SigningMethod {
        return SigningMethodAES128
    })
}

// Alg returns the signing method name
func (m *SigningMethodAES) Alg() string {
    return m.Name
}

// Verify in this case returns nil, because there is no defined way to verify an AES signing method.
// This is presently included to avoid breaking patterns established by other SigningMethods defined elsewhere.
// TODO - Define this
func (m *SigningMethodAES) Verify(signingString, signature string, key interface{}) error {
	// No validation errors. Signature is good.
	return nil
}

// Sign implements the Encrypt function for this signing method.
// key must be a map[string]string with indexes "key" and "iv".
func (m *SigningMethodAES) Sign(signingString string, key interface{}) (string, error) {
    var aesKey string
    var aesIv string
    keyMap := key.(map[string]string)
    
    if keyVal, keyOk := keyMap["key"]; keyOk {
        aesKey = keyVal
    }
    
    if ivVal, ivOk := keyMap["iv"]; ivOk {
        aesIv = ivVal
    }
    
	return m.Encrypt(signingString, aesKey, aesIv)
}

// Encrypt performs AES-128 (Rijndael) decryption on a raw, unencrypted string using a provided key and iv.
func (m *SigningMethodAES) Encrypt(rawString string, key string, iv string) (string, error) {
    aesBlockDecrypter, err := aes.NewCipher([]byte(key))
    if err != nil {
        return "", err
    }
    
    encrypted := make([]byte, len(rawString))    
    aesEncrypter := cipher.NewCFBEncrypter(aesBlockDecrypter, []byte(iv))
    aesEncrypter.XORKeyStream(encrypted, []byte(rawString))
    
    return string(encrypted), nil
}

// Decrypt performs AES-128 (Rijndael) decryption on an encrypted string using a provided key and iv.
func (m *SigningMethodAES) Decrypt(encryptedString string, key string, iv string) (string, error) {
    aesBlockDecrypter, err := aes.NewCipher([]byte(key))
    if err != nil {
        return "", err
    }
    
    decrypted := make([]byte, len(encryptedString))
    aesDecrypter := cipher.NewCFBDecrypter(aesBlockDecrypter, []byte(iv))
    aesDecrypter.XORKeyStream(decrypted, []byte(encryptedString))
    
    return string(decrypted), nil
}
