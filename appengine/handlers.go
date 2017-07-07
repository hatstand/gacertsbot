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
	"google.golang.org/appengine/log"
	"google.golang.org/appengine/memcache"
	"google.golang.org/appengine/urlfetch"
)

const (
	ACMEToken = "ACME_TOKEN"
	ACMEKey   = "ACME_KEY"
	ACMEURI   = "ACME_URI"

	LETS_ENCRYPT_STAGING = "https://acme-staging.api.letsencrypt.org/directory"
)

func init() {
	http.HandleFunc("/auth", wrapHTTPHandler(handleStartAuthorise))
	http.HandleFunc("/register", wrapHTTPHandler(handleRegister))
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

func deserializeKey(key []byte) (*rsa.PrivateKey, error) {
	return x509.ParsePKCS1PrivateKey(key)
}

func getOrCreateKey(c context.Context) (*rsa.PrivateKey, error) {
	item, err := memcache.Get(c, ACMEKey)
	if err == memcache.ErrCacheMiss {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("Failed to generate ACME RSA private key: %v", err)
		}
		// TODO: Register this key with LetsEncrypt here.
		err = memcache.Add(c, &memcache.Item{
			Key:   ACMEKey,
			Value: serializeKey(key),
		})
		if err != nil {
			return nil, fmt.Errorf("Failed to store ACME RSA private key: %v", err)
		}
		return key, nil
	} else if err != nil {
		return nil, fmt.Errorf("Failed to get ACME RSA private key: %v", err)
	}
	key, err := deserializeKey(item.Value)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse key from memcache: %v", err)
	}
	return key, nil
}

func createACMEClient(c context.Context) (*acme.Client, error) {
	key, err := getOrCreateKey(c)
	if err != nil {
		return nil, err
	}
	return &acme.Client{
		Key:          key,
		HTTPClient:   urlfetch.Client(c),
		DirectoryURL: LETS_ENCRYPT_STAGING,
	}, err
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

func handleRegister(c context.Context, w http.ResponseWriter, r *http.Request) error {
	client, err := createACMEClient(c)
	if err != nil {
		return fmt.Errorf("Failed to create ACME client: %v", err)
	}

	accountInfo := &acme.Account{
		Contact: []string{"mailto:john.maguire@gmail.com"},
	}

	account, err := client.Register(c, accountInfo, acme.AcceptTOS)
	if err != nil {
		return fmt.Errorf("Failed to register: %v", err)
	}

	io.WriteString(w, fmt.Sprintf("%v", account))
	return nil
}
