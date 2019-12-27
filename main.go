// Copyright 2018 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"cloud.google.com/go/storage"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/option"
)

var (
	vaultAddr     string
	gcsBucketName string
	httpClient    http.Client

	vaultSecretShares      int
	vaultSecretThreshold   int
	vaultStoredShares      int
	vaultRecoveryShares    int
	vaultRecoveryThreshold int

	kmsService *cloudkms.Service
	kmsKeyId   string

	storageClient *storage.Client

	userAgent = fmt.Sprintf("vault-init/1.1.0 (%s)", runtime.Version())
)

// InitRequest holds a Vault init request.
type InitRequest struct {
	SecretShares      int `json:"secret_shares"`
	SecretThreshold   int `json:"secret_threshold"`
	StoredShares      int `json:"stored_shares"`
	RecoveryShares    int `json:"recovery_shares"`
	RecoveryThreshold int `json:"recovery_threshold"`
}

// InitResponse holds a Vault init response.
type InitResponse struct {
	Keys       []string `json:"keys"`
	KeysBase64 []string `json:"keys_base64"`
	RootToken  string   `json:"root_token"`
}

func main() {
	log.Println("La Redoute: Starting the vault-init service.")

	vaultAddr = os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "https://127.0.0.1:8200"
	}

	vaultSecretShares = intFromEnv("VAULT_SECRET_SHARES", 5)
	vaultSecretThreshold = intFromEnv("VAULT_SECRET_THRESHOLD", 3)
	vaultStoredShares = intFromEnv("VAULT_STORED_SHARES", 1)
	vaultRecoveryShares = intFromEnv("VAULT_RECOVERY_SHARES", 1)
	vaultRecoveryThreshold = intFromEnv("VAULT_RECOVERY_THRESHOLD", 1)

	vaultInsecureSkipVerify := boolFromEnv("VAULT_SKIP_VERIFY", false)

	checkInterval := durFromEnv("CHECK_INTERVAL", 10*time.Second)

	gcsBucketName = os.Getenv("GCS_BUCKET_NAME")
	if gcsBucketName == "" {
		log.Fatal("GCS_BUCKET_NAME must be set and not empty")
	}

	kmsKeyId = os.Getenv("KMS_KEY_ID")
	if kmsKeyId == "" {
		log.Fatal("KMS_KEY_ID must be set and not empty")
	}

	/* KMS Config */
	kmsCtx, kmsCtxCancel := context.WithCancel(context.Background())
	defer kmsCtxCancel()
	kmsClient, err := google.DefaultClient(kmsCtx, "https://www.googleapis.com/auth/cloudkms")
	if err != nil {
		log.Println(err)
		return
	}

	kmsService, err = cloudkms.New(kmsClient)
	if err != nil {
		log.Println(err)
		return
	}
	kmsService.UserAgent = userAgent

	storageCtx, storageCtxCancel := context.WithCancel(context.Background())
	defer storageCtxCancel()
	storageClient, err = storage.NewClient(storageCtx,
		option.WithUserAgent(userAgent),
		option.WithScopes(storage.ScopeReadWrite),
	)
	if err != nil {
		log.Fatal(err)
	}

	httpClient = http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: vaultInsecureSkipVerify,
			},
		},
	}

	signalCh := make(chan os.Signal)
	signal.Notify(signalCh,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGKILL,
	)

	stop := func() {
		log.Printf("Shutting down")
		kmsCtxCancel()
		storageCtxCancel()
		os.Exit(0)
	}

	for {
		select {
		case <-signalCh:
			stop()
		default:
		}
		response, err := httpClient.Head(vaultAddr + "/v1/sys/health")

		if response != nil && response.Body != nil {
			response.Body.Close()
		}

		if err != nil {
			log.Println(err)
			time.Sleep(checkInterval)
			continue
		}

		switch response.StatusCode {
		case 200:
			log.Println("Vault is initialized.")
		case 429:
			log.Println("Vault is initialized and in STANDBY MODE")
		case 501:
			log.Println("Vault is not initialized.")
			log.Println("Initializing...")
			initialize()
		case 503:
			log.Println("Vault is sealed.")
			log.Println("Check our Vault configuration to validate autounseal.")	
		default:
			log.Printf("Vault is in an unknown state. Status code: %d", response.StatusCode)
		}

		if checkInterval <= 0 {
			log.Printf("Check interval set to less than 0, exiting.")
			stop()
		}

		log.Printf("Next check in %s", checkInterval)

		select {
		case <-signalCh:
			stop()
		case <-time.After(checkInterval):
		}
	}
}

func initialize() {
	initRequest := InitRequest{
		SecretShares:      vaultSecretShares,
		SecretThreshold:   vaultSecretThreshold,
		StoredShares:      vaultStoredShares,
		RecoveryShares:    vaultRecoveryShares,
		RecoveryThreshold: vaultRecoveryThreshold,
	}

	initRequestData, err := json.Marshal(&initRequest)
	if err != nil {
		log.Println(err)
		return
	}

	r := bytes.NewReader(initRequestData)
	request, err := http.NewRequest("PUT", vaultAddr+"/v1/sys/init", r)
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

	initRequestResponseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println(err)
		return
	}

	if response.StatusCode != 200 {
		log.Printf("init: non 200 status code: %d", response.StatusCode)
		return
	}

	var initResponse InitResponse

	if err := json.Unmarshal(initRequestResponseBody, &initResponse); err != nil {
		log.Println(err)
		return
	}

	log.Println("Encrypting unseal keys and the root token...")

	rootTokenEncryptRequest := &cloudkms.EncryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString([]byte(initResponse.RootToken)),
	}

	rootTokenEncryptResponse, err := kmsService.Projects.Locations.KeyRings.CryptoKeys.Encrypt(kmsKeyId, rootTokenEncryptRequest).Do()
	if err != nil {
		log.Println(err)
		return
	}

	unsealKeysEncryptRequest := &cloudkms.EncryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString(initRequestResponseBody),
	}

	unsealKeysEncryptResponse, err := kmsService.Projects.Locations.KeyRings.CryptoKeys.Encrypt(kmsKeyId, unsealKeysEncryptRequest).Do()
	if err != nil {
		log.Println(err)
		return
	}

	bucket := storageClient.Bucket(gcsBucketName)

	// Save the encrypted unseal keys.
	ctx := context.Background()
	unsealKeysObject := bucket.Object("unseal-keys.json.enc").NewWriter(ctx)
	defer unsealKeysObject.Close()

	_, err = unsealKeysObject.Write([]byte(unsealKeysEncryptResponse.Ciphertext))
	if err != nil {
		log.Println(err)
	}

	log.Printf("Unseal keys written to gs://%s/%s", gcsBucketName, "unseal-keys.json.enc")

	// Save the encrypted root token.
	rootTokenObject := bucket.Object("root-token.enc").NewWriter(ctx)
	defer rootTokenObject.Close()

	_, err = rootTokenObject.Write([]byte(rootTokenEncryptResponse.Ciphertext))
	if err != nil {
		log.Println(err)
	}

	log.Printf("Root token written to gs://%s/%s", gcsBucketName, "root-token.enc")

	log.Println("Initialization complete.")
}

func vaultAudit() {
	response, err := httpClient.Head(vaultAddr + "/v1/sys/health")

	if response != nil && response.Body != nil {
		response.Body.Close()
	}
}


func boolFromEnv(env string, def bool) bool {
	val := os.Getenv(env)
	if val == "" {
		return def
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		log.Fatalf("failed to parse %q: %s", env, err)
	}
	return b
}

func intFromEnv(env string, def int) int {
	val := os.Getenv(env)
	if val == "" {
		return def
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		log.Fatalf("failed to parse %q: %s", env, err)
	}
	return i
}

func durFromEnv(env string, def time.Duration) time.Duration {
	val := os.Getenv(env)
	if val == "" {
		return def
	}
	r := val[len(val)-1]
	if r >= '0' || r <= '9' {
		val = val + "s" // assume seconds
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		log.Fatalf("failed to parse %q: %s", env, err)
	}
	return d
}
