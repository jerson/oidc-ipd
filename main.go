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
	"github.com/google/uuid"
	jose "gopkg.in/square/go-jose.v2"
)

var (
	userName      = os.Getenv("OIDC_USER_NAME")
	userLastName  = os.Getenv("OIDC_USER_LAST_NAME")
	userEmail     = os.Getenv("OIDC_USER_EMAIL")
	userZoneInfo  = os.Getenv("OIDC_USER_ZONE_INFO")
	userLocale    = os.Getenv("OIDC_USER_LOCALE")
	user          = os.Getenv("OIDC_USER")
	issuer        = os.Getenv("OIDC_ISSUER")
	rsaPrivateKey *rsa.PrivateKey
	rsaPublicKey  *rsa.PublicKey
)
var defaultAddress = map[string]string{
	"region":  "WA",
	"country": "United States",
}
var authCodeScopeMap = make(map[string]string)
var authCodeClientMap = make(map[string]string)
var authCodeNonceMap = make(map[string]string)

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
	scope := r.URL.Query().Get("scope")
	nonce := r.URL.Query().Get("nonce")

	if clientID == "" || redirectURI == "" || state == "" || responseType == "" || scope == "" {
		http.Error(w, "Invalid request parameters", http.StatusBadRequest)
		return
	}
	authCode := uuid.New().String()
	authCodeScopeMap[authCode] = scope
	authCodeNonceMap[authCode] = nonce
	authCodeClientMap[authCode] = clientID

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

	if grantType != "authorization_code" {
		http.Error(w, "Invalid grant_type or code", http.StatusBadRequest)
		return
	}

	clientID, ok := authCodeClientMap[code]
	if !ok {
		http.Error(w, "Invalid or expired authorization code", http.StatusUnauthorized)
		return
	}

	scope, ok := authCodeNonceMap[code]
	if !ok {
		http.Error(w, "Missing scope for authorization code", http.StatusUnauthorized)
		return
	}

	nonce, ok := authCodeNonceMap[code]
	if !ok {
		http.Error(w, "Missing scope for authorization code", http.StatusUnauthorized)
		return
	}

	accessToken, err := generateAccessToken()
	if err != nil {
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}
	idToken, err := generateIDToken(clientID, scope, nonce)
	if err != nil {
		http.Error(w, "Failed to generate ID token", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
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

	response := map[string]interface{}{"sub": user}

	scope := "openid email profile address"
	if strings.Contains(scope, "email") {
		response["email"] = userEmail
		response["verified"] = true
	}

	if strings.Contains(scope, "profile") {
		response["name"] = userName
		response["nickname"] = user
		response["given_name"] = userName
		response["family_name"] = userLastName
		response["zoneinfo"] = userZoneInfo
		response["locale"] = userLocale
	}

	if strings.Contains(scope, "address") {
		response["address"] = defaultAddress
	}
	jsonResponse(w, response)
}

func generateAccessToken() (string, error) {
	claims := jwt.MapClaims{
		"sub": user,
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

func generateIDToken(clientID, scope, nonce string) (string, error) {
	claims := jwt.MapClaims{
		"sub": user,
		"aud": clientID,
		"iss": issuer,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour * 1).Unix(),
	}
	if strings.Contains(scope, "email") {
		claims["email"] = userEmail
		claims["verified"] = true
	}

	if strings.Contains(scope, "profile") {
		claims["name"] = userName
		claims["nickname"] = user
		claims["given_name"] = userName
		claims["family_name"] = userLastName
		claims["zoneinfo"] = userZoneInfo
		claims["locale"] = userLocale
	}

	if strings.Contains(scope, "address") {
		claims["address"] = defaultAddress
	}
	if nonce != "" {
		claims["nonce"] = nonce
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
