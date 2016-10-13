package hylaa

import (
	"regexp"
	"net/http"
	"github.com/hashicorp/vault/logical"
	"io/ioutil"
	"encoding/json"
	"bytes"
	"time"
	"strings"
	"github.com/hashicorp/go-uuid"
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
		keyListBytes,_ := json.Marshal(keyList)
		req.Body = ioutil.NopCloser(bytes.NewBuffer(keyListBytes))
	}else if req.Method == "POST" && tokenNewPattern.MatchString(req.URL.Path) {
		token, _ := uuid.GenerateUUID()
		req.URL.Path = "/v1/secret/" + token
		payload, _ := ioutil.ReadAll(req.Body)
		var data map[string]interface{}
		json.Unmarshal(payload, &data)
		keyList := data["key_list"].(map[string]interface {})
		keyListBytes,_ := json.Marshal(keyList)
		req.Body = ioutil.NopCloser(bytes.NewBuffer(keyListBytes))
	}
	return req
}

func ConvertToHylaaResponse(req *logical.Request,  resp interface{}) (interface{}) {
	if req.Operation == logical.ReadOperation && tokenReadPattern.MatchString(req.HylaaPath) {
		if(resp !=nil){
			return resp.(*logical.HTTPResponse).Data
		}
	}else if req.Operation == logical.UpdateOperation && tokenWritePattern.MatchString(req.HylaaPath) {
		var respBody interface{}
		json.Unmarshal([]byte(`{"status": "active"}`), &respBody)
		return respBody
	}else if req.Operation == logical.CreateOperation && tokenNewPattern.MatchString(req.HylaaPath) {
		token := strings.Replace(req.Path, "secret/", "", 1)
		var respBody = make(map[string]string)
		respBody["token"] = token
		respBody["create_date"] = time.Now().Format(time.RFC3339)
		return respBody
	}
	return resp
}


