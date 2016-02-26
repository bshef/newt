package newt

import (
    "fmt"
    "io/ioutil"
    "net/http"
	"reflect"
    "testing"
    "gitlab.trad.tradestation.com/bshef/newt"	
)

const (
    samplePublicKeyFile = "test/sample_key.pub"
    sampleKey           = "test/sample_key"
    validAES128Method   = "AES128"
)

var ( 
    newtTestDefaultKey  string
    defaultKeyFunc      newt.KeyFunc = func(t *newt.Token) (interface{}, error) { return newtTestDefaultKey, nil }
    emptyKeyFunc        newt.KeyFunc = func(t *newt.Token) (interface{}, error) { return nil, nil }
    nilKeyFunc          newt.KeyFunc
)

// nestTestData defines a collection of structures which hold relevant testing data.
var newtTestData = []struct {
    name        string
    tokenString string
    keyFunc     newt.KeyFunc
    claims      map[string]interface{}
    valid       bool
    parser      *newt.Parser
}{
    {
        "simple",
        "",
        defaultKeyFunc,
        map[string]interface{}{"foo": "bar"},
        true,
        &newt.Parser{ValidMethods: []string{validAES128Method}},
    },
    {
        "emptyKeyFunc",
        "",
        emptyKeyFunc,
        map[string]interface{}{"foo": "bar"},
        true,
        &newt.Parser{ValidMethods: []string{validAES128Method}},
    },
    {
        "nilKeyFunc",
        "",
        nilKeyFunc,
        map[string]interface{}{"foo": "bar"},
        false,
        &newt.Parser{ValidMethods: []string{validAES128Method}},
    },
}

func init() {
    // if _, err := ioutil.ReadFile(samplePublicKeyFile); err != nil {
    //     panic(err)
    // }
}

// makeSample generates a sample key based on provided claims data.
func makeSample(claims map[string]interface{}) string {
    aesKey, err := ioutil.ReadFile(sampleKey)
    if err != nil {
        panic(err.Error())
    }
    
    // Note: It's not generally advised to have key == iv,
    //       but for testing purposes, it's OK.
    var key = map[string]string {
        "key": string(aesKey),
        "iv": string(aesKey),
    }
    
    token := newt.New(newt.SigningMethodAES128)
    token.Claims = claims    
    sample, sErr := token.SignedString(key)
    
    if sErr != nil {
        panic(sErr.Error())
    }
    
    return sample
}

// TestParser_Parse should successfully parse a NEWT
func TestParser_Parse(t *testing.T) {
    for _, data := range newtTestData {
        t.Logf("\nTEST DATA: %s", data.name)
        
        if data.tokenString == "" {
            data.tokenString = makeSample(data.claims)
        }
        
        t.Logf("[%s]\tdata.tokenString: %v", data.name, data.tokenString)
        
        var token *newt.Token
        var err error
        
        // Perform the parse
        if data.parser != nil {
            token, err = data.parser.Parse(data.tokenString, data.keyFunc)
        } else {
            token, err = newt.Parse(data.tokenString, data.keyFunc)
        }
        
        t.Logf("[%s]\tToken parsed: %+v", data.name, token)
        
        // Test validation
        if !reflect.DeepEqual(data.claims, token.Claims) {
            t.Errorf(claimsMismatchErr, data.name, data.claims, token.Claims)
        }
        if data.valid && err != nil {
            t.Errorf(verifyErr, data.name, err, err)
        }
        if !data.valid && err == nil {
            t.Errorf(invalidTokenErr, data.name)
        }
        if data.valid && token.Signature == "" {
            t.Errorf(blankSignatureErr, data.name)
        }
    }
}

// TestParseRequest should successfully parse a NEWT from a request
func TestParseRequest(t *testing.T) {
    for _, data := range newtTestData {
        t.Logf("\nTEST DATA: %s", data.name)
        
        if data.tokenString == "" {
            data.tokenString = makeSample(data.claims)
        }
        
        t.Logf("[%s]\tdata.tokenString: %v", data.name, data.tokenString)
        
        // Create request
        r, _ := http.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %v", data.tokenString))
        
        t.Logf("[%s]\tRequest: %+v", data.name, r)
        
        // Perform the parse
		token, err := newt.ParseFromRequest(r, data.keyFunc)
        
        t.Logf("[%s]\tToken parsed: %+v", data.name, token)
        
        // Test validation
        if token == nil {
            t.Errorf(tokenNotFoundErr, data.name, err)
        }
        if !reflect.DeepEqual(data.claims, token.Claims) {
            t.Errorf(claimsMismatchErr, data.name, data.claims, token.Claims)
        }
        if data.valid && err != nil {
            t.Errorf(verifyErr, data.name, err, err)
        }
        if !data.valid && err == nil {
            t.Errorf(invalidTokenErr, data.name)
        }
        if data.valid && token.Signature == "" {
            t.Errorf(blankSignatureErr, data.name)
        }
    }
}