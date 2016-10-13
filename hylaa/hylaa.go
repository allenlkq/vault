package hylaa

import (
	"regexp"
	"net/http"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/helper/jsonutil"

	"io/ioutil"
	"bytes"
	"encoding/json"
)

var (
	authHeaderPattern = regexp.MustCompile("^Bearer ([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$")
	tokenReadPattern = regexp.MustCompile("^/token/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})/([a-zA-Z0-9_\\-\\|]+)$")
	tokenWritePattern = regexp.MustCompile("^/token/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$")
	tokenNewPattern = regexp.MustCompile("^/token/new$")
)


//TODO
func ConvertFromHylaaRequest(req *http.Request) (*http.Request) {
	// change Authentication bearer to X-Vault-Token
	if authHeaderPattern.MatchString(req.Header.Get("Authentication")) {
		xVaultToken := authHeaderPattern.FindStringSubmatch(req.Header.Get("Authentication"))[1]
		req.Header.Set("X-Vault-Token",xVaultToken)
	}

	var match []string
	var token string
	// read secret under token
	if req.Method == "GET" && tokenReadPattern.MatchString(req.URL.Path) {
		match = tokenReadPattern.FindStringSubmatch(req.URL.Path)
		token = match[1]
		keys := match[2]
		req.URL.Path = "/v1/secret/" + token + "/" + keys
	}else if req.Method == "PUT" && tokenWritePattern.MatchString(req.URL.Path) {
		match = tokenWritePattern.FindStringSubmatch(req.URL.Path)
		token = match[1]
		req.URL.Path = "/v1/secret/" + token
		payload, _ := ioutil.ReadAll(req.Body)
		var data map[string]interface{}
		json.Unmarshal(payload, &data)
		keyList := data["key_list"].(map[string]interface {})
		keyList["__append__"] = "1"
		keyListBytes,_ := jsonutil.EncodeJSON(keyList)
		req.Body = ioutil.NopCloser(bytes.NewBuffer(keyListBytes))
	}else if tokenNewPattern.MatchString(req.URL.Path) {

	}
	return req
}

func ConvertToHylaaResponse(req *logical.Request,  resp interface{}) (interface{}) {
	var respBody interface{} = resp
	if req.Operation == logical.ReadOperation && tokenReadPattern.MatchString(req.HylaaPath) {
		if(resp !=nil){
			respBody = resp.(*logical.HTTPResponse).Data
		}
	}else if req.Operation == logical.UpdateOperation && tokenWritePattern.MatchString(req.HylaaPath) {
		json.Unmarshal([]byte(`{"status": "active"}`), &respBody)
	}
	return respBody
}


