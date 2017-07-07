package appengine

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/net/context"
	"google.golang.org/appengine/datastore"
	"google.golang.org/appengine/log"
	"google.golang.org/appengine/urlfetch"
	"google.golang.org/appengine/user"
)

const (
	letsEncryptStagingURL = "https://acme-staging.api.letsencrypt.org/directory"
)

func createACMEClient(c context.Context) (*acme.Client, error) {
	// Get the account from Datastore.
	entityKey := datastore.NewKey(c, registeredAccountKind, registeredAccountIDName, 0, nil)
	account := RegisteredAccount{}

	switch err := datastore.Get(c, entityKey, &account); err {
	case datastore.ErrNoSuchEntity:
		log.Infof(c, "Account not found, creating new private key")
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("Failed to generate ACME RSA private key: %v", err)
		}
		account.Created = time.Now()
		account.PrivateKey = serializeKey(key)

	case nil:
		log.Infof(c, "Using existing account %s", account.AccountID)

	default:
		return nil, err
	}

	client := &acme.Client{
		Key:          deserializeKey(account.PrivateKey),
		HTTPClient:   urlfetch.Client(c),
		DirectoryURL: letsEncryptStagingURL,
	}

	if account.AccountID == "" {
		// Register with Let's Encrypt.
		email := user.Current(c).Email
		log.Infof(c, "Registering new account with email address %s", email)
		acc, err := client.Register(c, &acme.Account{
			Contact: []string{fmt.Sprintf("mailto:%s", email)},
		}, acme.AcceptTOS)
		if err != nil {
			return nil, fmt.Errorf("Failed to register: %v", err)
		}

		// Put it back in datastore.
		log.Infof(c, "Registered new account %s", acc.URI)
		account.AccountID = acc.URI
		if _, err := datastore.Put(c, entityKey, &account); err != nil {
			return nil, err
		}
	}

	return client, nil
}

func serializeKey(key *rsa.PrivateKey) []byte {
	return x509.MarshalPKCS1PrivateKey(key)
}

func deserializeKey(key []byte) *rsa.PrivateKey {
	ret, err := x509.ParsePKCS1PrivateKey(key)
	if err != nil {
		panic(err)
	}
	return ret
}
