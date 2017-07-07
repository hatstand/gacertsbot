package appengine

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/crypto/acme"
	"golang.org/x/net/context"
	"google.golang.org/appengine"
	"google.golang.org/appengine/datastore"
	"google.golang.org/appengine/log"
	"google.golang.org/appengine/memcache"
	"google.golang.org/appengine/urlfetch"
	"google.golang.org/appengine/user"
)

const (
	ACMEToken = "ACME_TOKEN"
	ACMEURI   = "ACME_URI"

	letsEncryptStagingURL = "https://acme-staging.api.letsencrypt.org/directory"

	registeredAccountKind   = "RegisteredAccount"
	registeredAccountIDName = "account"
)

type RegisteredAccount struct {
	PrivateKey []byte
	AccountID  string
}

func init() {
	http.HandleFunc("/auth", wrapHTTPHandler(handleStartAuthorise))
	http.HandleFunc("/.well-known", wrapHTTPHandler(handleChallenge))
}

type HandlerFunc func(context.Context, http.ResponseWriter, *http.Request) error

func wrapHTTPHandler(h HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := appengine.NewContext(r)
		if err := h(c, w, r); err != nil {
			log.Errorf(c, "%v", err)
			http.Error(w, "%v", 500)
		}
	}
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

func handleStartAuthorise(c context.Context, w http.ResponseWriter, r *http.Request) error {
	client, err := createACMEClient(c)
	if err != nil {
		return fmt.Errorf("Failed to create ACME client: %v", err)
	}

	auth, err := client.Authorize(c, r.URL.Host)
	if err != nil {
		return fmt.Errorf("Failed to authorize client: %v", err)
	}

	for _, challenge := range auth.Challenges {
		if challenge.Type == "http-01" {
			log.Infof(c, "Received http challenge: %v", challenge)
			memcache.Add(c, &memcache.Item{
				Key:   ACMEToken,
				Value: []byte(challenge.Token),
			})
			memcache.Add(c, &memcache.Item{
				Key:   ACMEURI,
				Value: []byte(auth.URI),
			})
			// TODO: Accept the HTTP-01 challenge
		}
	}
	return nil
}

func handleChallenge(c context.Context, w http.ResponseWriter, r *http.Request) error {
	item, err := memcache.Get(c, "ACME_TOKEN")
	if err != nil {
		http.Error(w, "No ACME challenge in progress", 400)
		return nil
	}

	client, err := createACMEClient(c)
	if err != nil {
		return fmt.Errorf("Failed to create ACME client: %v", err)
	}

	response, err := client.HTTP01ChallengeResponse(string(item.Value))
	if err != nil {
		return fmt.Errorf("Could not construct HTTP-01 challenge response: %v", err)
	}

	io.WriteString(w, response)
	return nil
}

func handleCheckStatus(c context.Context, w http.ResponseWriter, r *http.Request) error {
	item, err := memcache.Get(c, ACMEURI)
	if err != nil {
		http.Error(w, "No ACME authorisation in progress", 400)
		return nil
	}

	client, err := createACMEClient(c)
	if err != nil {
		return fmt.Errorf("Failed to create ACME client: %v", err)
	}

	auth, err := client.GetAuthorization(c, string(item.Value))
	if err != nil {
		return fmt.Errorf("Could not get current ACME authorization: %v", err)
	}

	io.WriteString(w, "Current status: "+auth.Status)
	return nil
}
