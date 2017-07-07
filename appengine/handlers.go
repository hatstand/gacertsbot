package appengine

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/net/context"
	"google.golang.org/appengine"
	"google.golang.org/appengine/datastore"
	"google.golang.org/appengine/log"
	"google.golang.org/appengine/urlfetch"
	"google.golang.org/appengine/user"
)

const (
	challengePathPrefix   = "/.well-known/acme-challenge/"
	letsEncryptStagingURL = "https://acme-staging.api.letsencrypt.org/directory"

	registeredAccountKind   = "RegisteredAccount"
	registeredAccountIDName = "account"
	challengeKind           = "Challenge"
)

type RegisteredAccount struct {
	Created    time.Time
	PrivateKey []byte
	AccountID  string
}

type Challenge struct {
	Type  string
	URI   string
	Token string

	Accepted  time.Time
	Responded time.Time
	Response  string
}

func init() {
	http.HandleFunc("/auth", wrapHTTPHandler(handleStartAuthorise))
	http.HandleFunc(challengePathPrefix, wrapHTTPHandler(handleChallenge))
}

type HandlerFunc func(context.Context, http.ResponseWriter, *http.Request) error

func wrapHTTPHandler(h HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := appengine.NewContext(r)
		if err := h(c, w, r); err != nil {
			log.Errorf(c, "%v", err)
			http.Error(w, err.Error(), 500)
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

func handleStartAuthorise(c context.Context, w http.ResponseWriter, r *http.Request) error {
	client, err := createACMEClient(c)
	if err != nil {
		return fmt.Errorf("Failed to create ACME client: %v", err)
	}

	log.Infof(c, "Authorizing %s", r.URL.Host)
	auth, err := client.Authorize(c, r.URL.Host)
	if err != nil {
		return fmt.Errorf("Failed to authorize client: %v", err)
	}

	for _, challenge := range auth.Challenges {
		if challenge.Type != "http-01" {
			continue
		}

		log.Infof(c, "Received http challenge %s, token %s", challenge.URI, challenge.Token)

		// Get a response ready.
		response, err := client.HTTP01ChallengeResponse(challenge.Token)
		if err != nil {
			return fmt.Errorf("Failed to create response to %s: %v", challenge.Token, err)
		}

		// Accept the challenge.
		challenge, err := client.Accept(c, challenge)
		if err != nil {
			return fmt.Errorf("Failed to accept challenge: %v", err)
		}
		log.Infof(c, "Accepted challenge")

		// Record the challenge and response in datastore.
		if _, err := datastore.Put(c, datastore.NewKey(c, challengeKind, challenge.Token, 0, nil), &Challenge{
			Type:     challenge.Type,
			URI:      challenge.URI,
			Token:    challenge.Token,
			Accepted: time.Now(),
			Response: response,
		}); err != nil {
			return fmt.Errorf("Failed to save challenge: %v", err)
		}
		break
	}
	return nil
}

func handleChallenge(c context.Context, w http.ResponseWriter, r *http.Request) error {
	token := strings.TrimPrefix(r.URL.Path, challengePathPrefix)

	// Find the challenge in datastore.
	entityKey := datastore.NewKey(c, challengeKind, token, 0, nil)
	challenge := Challenge{}
	if err := datastore.Get(c, entityKey, &challenge); err != nil {
		return err
	}

	log.Infof(c, "Responding to challenge %s with %s", challenge.URI, challenge.Response)
	io.WriteString(w, challenge.Response)

	challenge.Responded = time.Now()
	_, err := datastore.Put(c, entityKey, &challenge)
	return err
}
