# Ninja Encrypted Web Token (NEWT)
A proprietary token flavor of [JWT](http://jwt.io/),
based off of https://github.com/dgrijalva/jwt-go

# Information
## What is a NEWT?
It's a signed JSON object that does something useful.
In particular, it's designed to be used as an authentication token.
A token is made of three parts, separated by `.`s.
The first two parts are JSON objects that have been [base64url](http://tools.ietf.org/html/rfc4648) encoded.
The last part is the signature.

The first part is called the header.
It contains the necesssary information for verifying the last part, the signature.
In this case, NEWTs only support one method of encryption: AES-128 (Rijndael), but this could be expanded in the future.

The part in the middle is the interesting segment.
It's called the Claims and contains the actual stuff you care about.
Refer to [the RFC](http://self-issued.info/docs/draft-jones-json-web-token.html)
for information about reserved keys and the proper way to add your own.

## What's in the box?
This library supports the parsing and verification as well as the generation and signing of NEWTs.
Current supported signing algorithm(s) are AES-128, though hooks are present for adding your own.

## NEWT vs JWT
Why not just use a JWT, then? Well, firstly, the NEWT was designed to be a proprietary format.
And the major difference is that while JWT supports many types of signing methods,
it does not (yet) support AES; the NEWT does.

## Format
### Header
```
{
    "alg": "AES128",
    "typ": "NEWT"
}
```
### Payload
```
{
    "foo": "bar"
}
```

### Example NEWT
```
eyJhbGciOiJBRVMxMjgiLCJ0eXAiOiJORVdUIn0.eyJmb28iOiJiYXIifQ.l�����)�¶R��M�bH▲�L�H�h"����Qu���"�7���§�☻`P�OH���2▲�10-�
```

- The header and payload are each encrypted using the AES-128 (Rijndael) standard. 
- A third segment contains signature verification information, and is also encrypted with AES-128.
- The header and payload are Base64-encoded. This allows each segment to be placed in a single string with delimiters.
- These three segments are separated by a `.` delimiter.

## Usage

### Import
`import gitlab.trad.tradestation.com/bshef/newt`

### Create a Token
```
// Structure to hold key information for AES-128 encryption.
var key = map[string]string {
    "key": string(aesKey),
    "iv": string(aesKey),
}

// Claims payload.
var claims = map[string]interface{}{"foo": "bar"}

// Create token.
token := newt.New(newt.SigningMethodAES128)
token.Claims = claims  
encryptedTokenString, _ := token.SignedString(key)
```

### Parse a Request

```
// Create request.
r, _ := http.NewRequest("GET", "/", nil)
r.Header.Set("Authorization", fmt.Sprintf("Bearer %v", encryptedTokenString))

// A newt.KeyFunc can be used to validate the signing method.
// In this case, the function does nothing and won't report errors.
// A newt.KeyFunc MUST be supplied, even if it does nothing.
var keyFunc newt.KeyFunc = func(t *newt.Token) (interface{}, error) { return nil, nil }

// Parse the token from the request.
parsedToken, err := newt.ParseFromRequest(req, keyFunc)

// Validate success of token parsing.
success := (err == nil && parsedToken.Valid)
```

## Test
`go test -v`

Output:
```
=== RUN   TestParser_Parse
--- PASS: TestParser_Parse (0.00s)
        parser_test.go:94:
                TEST DATA: simple
�OH���2▲�10-�r_test.go:100: [simple]    data.tokenString: eyJhbGciOiJBRVMxMjgiLCJ0eXAiOiJORVdUIn0.eyJmb28iOiJiYXIifQ.l�����)�¶R��M�bH▲�L�H�h"����Qu���"�7���§�☻`P
�OH���2▲�10-� Valid:true}82044dc0 Header:map[alg:AES128 typ:NEWT] Claims:map[foo:bar] Signature:l�����)�¶R��M�bH▲�L�H�h"����Qu���"�7���§�☻`P�h"����Qu���"�7���§�☻`P
        parser_test.go:94:
                TEST DATA: emptyKeyFunc
�OH���2▲�10-�r_test.go:100: [emptyKeyFunc]      data.tokenString: eyJhbGciOiJBRVMxMjgiLCJ0eXAiOiJORVdUIn0.eyJmb28iOiJiYXIifQ.l�����)�¶R��M�bH▲�L�H�h"����Qu���"�7���§�☻`P
�OH���2▲�10-� Valid:true}82044dc0 Header:map[alg:AES128 typ:NEWT] Claims:map[foo:bar] Signature:l�����)�¶R��M�bH▲�L�H�h"����Qu���"�7���§�☻`P�bH▲�L�H�h"����Qu���"�7���§�☻`P
        parser_test.go:94:
                TEST DATA: nilKeyFunc
�OH���2▲�10-�r_test.go:100: [nilKeyFunc]        data.tokenString: eyJhbGciOiJBRVMxMjgiLCJ0eXAiOiJORVdUIn0.eyJmb28iOiJiYXIifQ.l�����)�¶R��M�bH▲�L�H�h"����Qu���"�7���§�☻`P
�OH���2▲�10-� Method:0xc082044dc0 Header:map[alg:AES128 typ:NEWT] Claims:map[foo:bar] Signature: Valid:false}yJmb28iOiJiYXIifQ.l�����)�¶R��M�bH▲�L�H�h"����Qu���"�7���§�☻`P
=== RUN   TestParseRequest
--- PASS: TestParseRequest (0.00s)
        parser_test.go:133:
                TEST DATA: simple
�OH���2▲�10-�r_test.go:139: [simple]    data.tokenString: eyJhbGciOiJBRVMxMjgiLCJ0eXAiOiJORVdUIn0.eyJmb28iOiJiYXIifQ.l�����)�¶R��M�bH▲�L�H�h"����Qu���"�7���§�☻`P
        parser_test.go:145: [simple]    Request: &{Method:GET URL:/ Proto:HTTP/1.1 ProtoMajor:1 ProtoMinor:1 Header:map[Authorization:[Bearer eyJhbGciOiJBRVMxMjgiLCJ0eXAiOiJORVdUIn0.eyJmb28iOiJiYXIifQ.l�����)�¶R��M�bH▲�L�H�h"����Qu���"�7����OH���2▲�10-�]] Body:<nil> ContentLength:0 TransferEncoding:[] Close:false Host: Form:map[] PostForm:map[] MultipartForm:<nil> Trailer:map[] RemoteAddr: RequestURI: TLS:<nil> Cancel:<nil>}
�OH���2▲�10-� Valid:true}82044dc0 Header:map[alg:AES128 typ:NEWT] Claims:map[foo:bar] Signature:l�����)�¶R��M�bH▲�L�H�h"����Qu���"�7���§�☻`P�h"����Qu���"�7���§�☻`P
        parser_test.go:133:
                TEST DATA: emptyKeyFunc
�OH���2▲�10-�r_test.go:139: [emptyKeyFunc]      data.tokenString: eyJhbGciOiJBRVMxMjgiLCJ0eXAiOiJORVdUIn0.eyJmb28iOiJiYXIifQ.l�����)�¶R��M�bH▲�L�H�h"����Qu���"�7���§�☻`P
        parser_test.go:145: [emptyKeyFunc]      Request: &{Method:GET URL:/ Proto:HTTP/1.1 ProtoMajor:1 ProtoMinor:1 Header:map[Authorization:[Bearer eyJhbGciOiJBRVMxMjgiLCJ0eXAiOiJORVdUIn0.eyJmb28iOiJiYXIifQ.l�����)�¶R��M�bH▲�L�H�h"����Qu��OH���2▲�10-�]] Body:<nil> ContentLength:0 TransferEncoding:[] Close:false Host: Form:map[] PostForm:map[] MultipartForm:<nil> Trailer:map[] RemoteAddr: RequestURI: TLS:<nil> Cancel:<nil>}
�OH���2▲�10-� Valid:true}82044dc0 Header:map[alg:AES128 typ:NEWT] Claims:map[foo:bar] Signature:l�����)�¶R��M�bH▲�L�H�h"����Qu���"�7���§�☻`P�bH▲�L�H�h"����Qu���"�7���§�☻`P
        parser_test.go:133:
                TEST DATA: nilKeyFunc
�OH���2▲�10-�r_test.go:139: [nilKeyFunc]        data.tokenString: eyJhbGciOiJBRVMxMjgiLCJ0eXAiOiJORVdUIn0.eyJmb28iOiJiYXIifQ.l�����)�¶R��M�bH▲�L�H�h"����Qu���"�7���§�☻`P
        parser_test.go:145: [nilKeyFunc]        Request: &{Method:GET URL:/ Proto:HTTP/1.1 ProtoMajor:1 ProtoMinor:1 Header:map[Authorization:[Bearer eyJhbGciOiJBRVMxMjgiLCJ0eXAiOiJORVdUIn0.eyJmb28iOiJiYXIifQ.l�����)�¶R��M�bH▲�L�H�h"����Qu��OH���2▲�10-�]] Body:<nil> ContentLength:0 TransferEncoding:[] Close:false Host: Form:map[] PostForm:map[] MultipartForm:<nil> Trailer:map[] RemoteAddr: RequestURI: TLS:<nil> Cancel:<nil>}
�OH���2▲�10-� Method:0xc082044dc0 Header:map[alg:AES128 typ:NEWT] Claims:map[foo:bar] Signature: Valid:false}yJmb28iOiJiYXIifQ.l�����)�¶R��M�bH▲�L�H�h"����Qu���"�7���§�☻`P
PASS
ok      gitlab.com/bshef/newt   0.052s
```

Note that the output can be a little confused due to invalid escape characters generated as a result of AES-128 encryption.
It may be prudent to add another layer of Base-64 encoding on top of the AES-128 encrypted string to make it more output-friendly.

