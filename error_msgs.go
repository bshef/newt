package newt

const (
    invalidNumSegmentsErr     = "Token contains an invalid number of segments."
    containsBearerErr         = "Token string should not contain 'bearer'."
    malformedErr              = "Token is malformed."
    signingMethodUnavailErr   = "Signing method (alg) is unavailable."
    signingMethodUnspecErr    = "Signing method (alg) is unspecified."
    signingMethodInvalidErr   = "Signing method (alg) %v is invalid."
    noKeyFuncErr              = "No KeyFunc was provided."
    tokenExpErr               = "Token is expired."
    futureTokenErr            = "Token is not valid yet."
    invalidSignatureErr       = "Invalid signature."
)

const (
    claimsMismatchErr   = "[%v] Claims mismatch. Expecting: %v  Got: %v"
    verifyErr           = "[%v] Error while verifying token: %T:%v"
    invalidTokenErr     = "[%v] Invalid token passed validation"
    blankSignatureErr   = "[%v] Signature is left unpopulated after parsing"
    tokenNotFoundErr    = "[%v] Token was not found: %v"
)
