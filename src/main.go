package main

import (
	"bytes"
	"encoding/json"
	"log"
	"fmt"
	"crypto/tls"
	"io/ioutil"
	"net/http"
)

type auditRequest struct {
	AuditType   string `json:"type"`
	Description string `json:"description"`
	Options     options `json:"options"`
}

type auditResponse struct {
	File File
}


type options struct {
	FilePath string `json:"file_path"`
} 

type File struct {
	Type		string `json:"type"`
	Description	string `json:"description"`
	Options		options `json:"options"`
}

var (
	httpClient    http.Client
	vaultInsecureSkipVerify	bool
	vaultToken string
	auditType string
	auditDescription string
	auditPath string
	vaultAddr string
	auditName string
)

func main() {

	auditType 		 		= "file"
	auditDescription 		= "Teste teste teste teste"
	auditPath 		 		= "stdout"
	vaultAddr 		 		= "https://vault.security.svc.cluster.local:8200"
	vaultToken 		 		= "s.Af6j1Yq6vN8uKDNrJG1KrUwI"
	vaultInsecureSkipVerify = true
	auditName 		 		= "la-redoute"

	httpClient = http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: vaultInsecureSkipVerify,
			},
		},
	}

	auditRequest := auditRequest{
		AuditType:   auditType,
		Description: auditDescription,
		Options:     options{FilePath: auditPath},
	}

	auditRequestData, err := json.Marshal(&auditRequest)
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Println(string(auditRequestData))
	
	r := bytes.NewReader(auditRequestData)
	request, err := http.NewRequest("PUT", vaultAddr + "/v1/sys/audit/" + auditName, r)
	request.Header.Set("X-Vault-Token", vaultToken)
	log.Println("Request: " + vaultAddr + "/v1/sys/audit/" + auditName)
	
	if err != nil {
		log.Println(err)
		return
	}

	response, err := httpClient.Do(request)
	if err != nil {
		log.Println(err)
		return
	}
	defer response.Body.Close()

	auditRequestResponseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println(err)
		return
	}

	if response.StatusCode != 200 {
		log.Printf("init: non 200 status code: %d", response.StatusCode)
		return
	}

	var auditResponse auditResponse

	if err := json.Unmarshal(auditRequestResponseBody, &auditResponse); err != nil {
		log.Println(err)
		return
	}

	log.Println("Vault audit: Enable with sucess!")
}
