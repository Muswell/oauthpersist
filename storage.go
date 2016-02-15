// Oauthtokens provides functions that store and retrieve tokens from the golang.org/oauth2 package.
// This package borrows from the Redis storage config created by Aaron Torres.
// https://gist.github.com/agtorre/350c5b4ce0ccebc5ac0f
package oauthpersist

import (
	"encoding/csv"
	"errors"
	"fmt"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"net/http"
	"os"
	"path"
	"time"
)

// Config combines an oauth2.Config pointer with a TokenStorage interface.
type Config struct {
	*oauth2.Config
	// Storage stores and retrieves tokens
	Storage TokenStorage
}

// Exchange is a wrapper function for oauth2.Config.Exchange.
// Underneath the hood it calls TokenStorage.StoreToken when a valid token is exchanged.
func (c *Config) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	token, err := c.Config.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}
	if err := c.Storage.StoreToken(token); err != nil {
		return nil, err
	}
	return token, nil
}

// Client is a wrapper function for oauth2.Config.Client
func (c *Config) Client(ctx context.Context, t *oauth2.Token) *http.Client {
	return oauth2.NewClient(ctx, c.TokenSource(ctx, t))
}

// TokenSource returns a ReuseTokenSource.
func (c *Config) TokenSource(ctx context.Context, t *oauth2.Token) oauth2.TokenSource {
	tts := &TokenStorageSource{
		source: c.Config.TokenSource(ctx, t),
		config: c,
	}
	return oauth2.ReuseTokenSource(t, tts)
}

// TokenStorage is an interface designed to store tokens
// in a persistence layer and to recreate tokens from that persisted data.
type TokenStorage interface {
	// StoreToken attempts to persist a token for future retrieval.
	// If persistence is not successful it returns an error.
	StoreToken(token *oauth2.Token) error
	// RestoreToken returns a token from persisted data.
	RestoreToken() (*oauth2.Token, error)
}

type TokenStorageSource struct {
	source oauth2.TokenSource
	config *Config
}

func (t *TokenStorageSource) Token() (*oauth2.Token, error) {
	token, err := t.source.Token()
	if err != nil {
		return nil, err
	}
	if err := t.config.Storage.StoreToken(token); err != nil {
		return nil, err
	}
	return token, nil
}

// FileTokenStorage stores tokens in csv files
type FileTokenStorage struct {
	// StoragePath is the folder path where the token file will be stored.
	StoragePath string
	// TokenId is a unique identifier for a token, usually a user id.
	TokenId interface{}
}

// FileTokenStorage.StoreToken saves a token as a csv file
func (store *FileTokenStorage) StoreToken(token *oauth2.Token) error {
	if store.StoragePath == "" {
		return errors.New("Cannot store token: StoragePath not set.")
	}

	tokenIdStr := fmt.Sprint(store.TokenId)
	if store.TokenId == nil || tokenIdStr == "" {
		return errors.New("Cannot store token: TokenId not set.")
	}

	filename := path.Join(store.StoragePath, tokenIdStr+".csv")
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	record := []string{token.AccessToken, token.RefreshToken, token.Expiry.String(), token.TokenType}
	w := csv.NewWriter(f)
	if err = w.Write(record); err != nil {
		return err
	}
	w.Flush()

	if err := w.Error(); err != nil {
		return err
	}
	return nil
}

// FileTokenStorage.RestoreToken returns an oauth2.Token from a file.
func (store *FileTokenStorage) RestoreToken() (*oauth2.Token, error) {
	if store.StoragePath == "" {
		return nil, errors.New("Cannot restore token: StoragePath not set.")
	}

	tokenIdStr := fmt.Sprint(store.TokenId)
	if store.TokenId == nil || tokenIdStr == "" {
		return nil, errors.New("Cannot restore token: TokenId not set.")
	}

	filename := path.Join(store.StoragePath, tokenIdStr+".csv")

	f, err := os.Open(filename)

	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	record, err := r.Read()

	if err != nil {
		return nil, err
	}

	if len(record) < 4 {
		return nil, errors.New("Cannot restore token: File does not contain all fields.")
	}

	expiry, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", record[2])
	if err != nil {
		return nil, err
	}

	token := &oauth2.Token{
		AccessToken:  record[0],
		RefreshToken: record[1],
		Expiry:       expiry,
		TokenType:    record[3],
	}

	return token, nil
}

// FileTokenStorage.RestoreToken returns an oauth2.Token from a file.
func (store *FileTokenStorage) DeleteToken() error {
	if store.StoragePath == "" {
		return errors.New("Cannot delete token: StoragePath not set.")
	}

	tokenIdStr := fmt.Sprint(store.TokenId)
	if store.TokenId == nil || tokenIdStr == "" {
		return errors.New("Cannot delete token: TokenId not set.")
	}

	filename := path.Join(store.StoragePath, tokenIdStr+".csv")
	return os.Remove(filename)
}
