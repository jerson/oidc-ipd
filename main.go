package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	jose "gopkg.in/square/go-jose.v2"
)

var (
	name          = os.Getenv("OIDC_NAME")
	username      = os.Getenv("OIDC_USERNAME")
	issuer        = os.Getenv("OIDC_ISSUER")
	clientIDApp   = os.Getenv("OIDC_CLIENT_ID")
	authCode      = os.Getenv("OIDC_AUTH_CODE")
	rsaPrivateKey *rsa.PrivateKey
	rsaPublicKey  *rsa.PublicKey
)

func initKeys() error {
	var err error
	rsaPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	rsaPublicKey = &rsaPrivateKey.PublicKey
	return nil
}

func logRequest(r *http.Request) {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Failed to read request body: %v", err)
		return
	}

	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	logData := map[string]interface{}{
		"method":  r.Method,
		"url":     r.URL.String(),
		"headers": r.Header,
		"body":    string(bodyBytes),
	}

	logDataJSON, err := json.Marshal(logData)
	if err != nil {
		log.Printf("Failed to marshal request log data: %v", err)
		return
	}

	log.Printf("%s", logDataJSON)
}

func discoveryHandler(w http.ResponseWriter, r *http.Request) {
	logRequest(r)

	response := map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"userinfo_endpoint":                     issuer + "/userinfo",
		"jwks_uri":                              issuer + "/jwks.json",
		"response_types_supported":              []string{"code", "token", "id_token", "code id_token", "code token", "id_token token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}
	jsonResponse(w, response)
}

func jwksHandler(w http.ResponseWriter, r *http.Request) {
	logRequest(r)

	jwk := jose.JSONWebKey{
		Key:       rsaPublicKey,
		KeyID:     "1",
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
	keySet := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}
	jsonResponse(w, keySet)
}

func authorizeHandler(w http.ResponseWriter, r *http.Request) {
	logRequest(r)

	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	responseType := r.URL.Query().Get("response_type")
	if clientID == "" {
		clientID = clientIDApp
	}

	if clientID == "" || redirectURI == "" || state == "" || responseType == "" {
		http.Error(w, "Invalid request parameters", http.StatusBadRequest)
		return
	}

	redirectURL, _ := url.Parse(redirectURI)
	params := url.Values{}
	params.Add("code", authCode)
	params.Add("state", state)
	redirectURL.RawQuery = params.Encode()
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func logFormValues(r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		log.Printf("Failed to parse form: %v", err)
		return
	}

	formData := make(map[string]interface{})

	for key, values := range r.Form {
		formData[key] = values
	}

	formDataJSON, err := json.Marshal(formData)
	if err != nil {
		log.Printf("Failed to marshal form data: %v", err)
		return
	}

	log.Printf("%s", formDataJSON)
}
func tokenHandler(w http.ResponseWriter, r *http.Request) {
	logRequest(r)

	logFormValues(r)
	grantType := r.FormValue("grant_type")
	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	if clientID == "" {
		clientID = clientIDApp
	}

	if grantType != "authorization_code" || code != authCode {
		http.Error(w, "Invalid grant_type or code", http.StatusBadRequest)
		return
	}

	accessToken, err := generateAccessToken()
	if err != nil {
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}
	idToken, err := generateIDToken(clientID)
	if err != nil {
		http.Error(w, "Failed to generate ID token", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"aud":          clientID,
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	}
	jsonResponse(w, response)
}

func userInfoHandler(w http.ResponseWriter, r *http.Request) {
	logRequest(r)

	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	if tokenString == "" {
		http.Error(w, "Missing access token", http.StatusUnauthorized)
		return
	}

	response := map[string]interface{}{
		"sub":   username,
		"name":  name,
		"email": username,
	}
	jsonResponse(w, response)
}

func generateAccessToken() (string, error) {
	claims := jwt.MapClaims{
		"sub": username,
		"iss": issuer,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour * 1).Unix(),
	}
	log.Printf("Generating access token with claims: %v", claims)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "1"
	tokenString, err := token.SignedString(rsaPrivateKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func generateIDToken(clientID string) (string, error) {
	claims := jwt.MapClaims{
		"sub": username,
		"aud": clientID,
		"iss": issuer,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour * 1).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "1"
	tokenString, err := token.SignedString(rsaPrivateKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")

	logData, err := json.Marshal(data)
	if err != nil {
		log.Printf("Failed to marshal log data: %v", err)
	} else {
		log.Printf("%s", logData)
	}

	err = json.NewEncoder(w).Encode(data)
	if err != nil {
		logErrorData, _ := json.Marshal(map[string]interface{}{
			"error": err.Error(),
		})
		log.Printf("%s", logErrorData)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func main() {
	err := initKeys()
	if err != nil {
		log.Fatalf("Failed to initialize keys: %v", err)
	}

	http.HandleFunc("/.well-known/openid-configuration", discoveryHandler)
	http.HandleFunc("/jwks.json", jwksHandler)
	http.HandleFunc("/authorize", authorizeHandler)
	http.HandleFunc("/token", tokenHandler)
	http.HandleFunc("/userinfo", userInfoHandler)

	fmt.Printf("OIDC ID Provider is running at %s\n", issuer)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
