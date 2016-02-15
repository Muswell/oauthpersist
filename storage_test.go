package oauthpersist

import (
	"encoding/base64"
	"fmt"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestFileTokenStorage(t *testing.T) {
	token := &oauth2.Token{
		AccessToken:  "abc",
		RefreshToken: "def",
		Expiry:       time.Now().Add(time.Hour * 1),
		TokenType:    "bearer",
	}

	fmt.Sprint()
	fileStore := FileTokenStorage{}

	// Expecting No StoragePath Errors
	err := fileStore.StoreToken(token)
	if err == nil {
		t.Error("Expected an error from FileTokenStorage.StoreToken with no StoragePath set")
	}

	if !strings.Contains(err.Error(), "StoragePath not set") {
		t.Errorf("fileStore.StoreToken unexpected token got %s expected %s", err.Error(), "StoragePath not set")
	}

	_, err = fileStore.RestoreToken()
	if err == nil {
		t.Errorf("Expected error from FileTokenStorage.RestoreToken with no TokenId")
	}

	if !strings.Contains(err.Error(), "StoragePath not set") {
		t.Errorf("fileStore.RestoreToken unexpected error got %s expected %s", err.Error(), "StoragePath not set")
	}

	if fileStore.DeleteToken() == nil {
		t.Errorf("fileStore.DeleteToken expected a StoragePath error.")
	}

	fileStore.StoragePath = "fakeFolder"

	// Expecting no TokenId errors
	err = fileStore.StoreToken(token)
	if err == nil {
		t.Error("Expected an error from FileTokenStorage.StoreToken with no TokenId set")
	}

	if !strings.Contains(err.Error(), "TokenId not set") {
		t.Errorf("fileStore.StoreToken unexpected token got %s expected %s", err.Error(), "TokenId not set")
	}

	_, err = fileStore.RestoreToken()
	if err == nil {
		t.Errorf("Expected error from FileTokenStorage.RestoreToken with no TokenId set")
	}

	if !strings.Contains(err.Error(), "TokenId not set") {
		t.Errorf("fileStore.RestoreToken unexpected error got %s expected %s", err.Error(), "TokenId not set")
	}

	if fileStore.DeleteToken() == nil {
		t.Errorf("fileStore.DeleteToken expected a TokenId error.")
	}

	fileStore.TokenId = 123
	// Expecting IO errors
	err = fileStore.StoreToken(token)
	if err == nil {
		t.Error("Expected an error from FileTokenStorage.StoreToken with invalid folder path")
	}

	_, err = fileStore.RestoreToken()
	if err == nil {
		t.Errorf("Expected error from FileTokenStorage.RestoreToken with invalid folder path")
	}

	// Expecting file storage and retrieval success
	fileStore.StoragePath = "testtokens"

	err = fileStore.StoreToken(token)

	if err != nil {
		t.Errorf("FileTokenStorage.StoreToken returned a non nil error %v", err)
	}

	defer fileStore.DeleteToken()

	restoredToken, err := fileStore.RestoreToken()

	if err != nil {
		t.Errorf("FileTokenStorate.RestoreToken returned a non nil error %v", err)
	}

	if restoredToken.AccessToken != token.AccessToken {
		t.Errorf("fileStore.RestoreToken unexpected AccessToken got %s expected %s",
			restoredToken.AccessToken, token.AccessToken)
	}

	if restoredToken.RefreshToken != token.RefreshToken {
		t.Errorf("fileStore.RestoreToken unexpected RefreshToken got %s expected %s",
			restoredToken.RefreshToken, token.RefreshToken)
	}

	if restoredToken.Expiry != token.Expiry {
		t.Errorf("fileStore.RestoreToken unexpected Expiry got %v expected %v",
			restoredToken.Expiry, token.Expiry)
	}

	if restoredToken.TokenType != token.TokenType {
		t.Errorf("fileStore.RestoreToken unexpected TokenType got %s expected %s",
			restoredToken.TokenType, token.TokenType)
	}
}

func TestConfigStorage(t *testing.T) {
	storage := &FileTokenStorage{
		StoragePath: "testtokens",
		TokenId:     123,
	}
	clientId, clientSecret, redirectUrl := "clientId", "clientSecret", "http://redirect.com"
	authHeader := base64.StdEncoding.EncodeToString([]byte("clientId:clientSecret"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Authorization"), authHeader) {
			w.WriteHeader(http.StatusForbidden)
			return
		} else {
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				t.Errorf("Failed reading request body: %s.", err)
			}

			values, err := url.ParseQuery(string(body))
			if err != nil {
				t.Errorf("Failed parsing request: %s.", err)
			}

			switch values.Get("grant_type") {
			case "authorization_code":
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"access_token":"Jzxbkqqcvjqik2IMxGFEE1cuaos--",
					"token_type":"bearer",
					"expires_in":10,
					"refresh_token":"AOiRUlJn_qOmByVGTmUpwcMKW3XDcipToOoHx2wRoyLgJC_RFlA-",
					"xoauth_yahoo_guid":"JT4FACLQZI2OCE"}`))
				return
			case "refresh_token":
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"access_token":"aNewAccessToken",
					"token_type":"bearer",
					"expires_in":3600,
					"refresh_token":"aNewRefreshToken",
					"xoauth_yahoo_guid":"JT4FACLQZI2OCE"}`))
				return
			default:
				http.Error(w, "grant type is not supported: "+values.Get("grant_type"), http.StatusBadRequest)
				return
			}

		}
	}))
	defer server.Close()

	config := Config{
		Config: &oauth2.Config{
			ClientID:     clientId,
			ClientSecret: clientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  server.URL,
				TokenURL: server.URL,
			},
			RedirectURL: redirectUrl,
		},
		Storage: storage,
	}

	defer storage.DeleteToken()
	token, err := config.Exchange(oauth2.NoContext, "code")

	if err != nil {
		if err != nil {
			t.Errorf("Config.Exchange returned a non nil error %v", err)
		}
	}

	if token.AccessToken != "Jzxbkqqcvjqik2IMxGFEE1cuaos--" {
		t.Errorf("Config.Exchange token has incorrect AccessToken, got %s expected %s", token.AccessToken, "Jzxbkqqcvjqik2IMxGFEE1cuaos--")
	}

	client := config.Client(oauth2.NoContext, token)
	if client == nil {
		t.Error("Config.Client returned a nil client")
	}

	source := TokenStorageSource{
		config: &config,
		source: config.TokenSource(oauth2.NoContext, token),
	}

	time.Sleep(10)
	sourceToken, err := source.Token()
	if err != nil {
		t.Error("TokenSource.Token returned an error %v", err)
	}

	if sourceToken.AccessToken != "aNewAccessToken" {
		t.Errorf("Expected a token refresh of access token. Got %s epected %s", sourceToken.AccessToken, "aNewAccessToken")
	}
}
