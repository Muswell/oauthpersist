package oauthtokens

import (
	"fmt"
	"golang.org/x/oauth2"
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
	fileStore := FileTokenStorage{
		TokenId: 123,
	}
	err := fileStore.StoreToken(token)
	if err == nil {
		t.Error("Expected an error from FileTokenStorage.StoreToken with no StoragePath set")
	}

	if !strings.Contains(err.Error(), "StoragePath not set") {
		t.Errorf("fileStore.StoreToken unexpected token got %s expected %s", err.Error(), "StoragePath not set")
	}

	_, err = fileStore.RestoreToken()
	if err == nil {
		t.Errorf("Expected error from FileTokenStorage.RestoreToken")
	}

	if !strings.Contains(err.Error(), "StoragePath not set") {
		t.Errorf("fileStore.RestoreToken unexpected error got %s expected %s", err.Error(), "StoragePath not set")
	}

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
