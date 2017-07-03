package appengine

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"

	"golang.org/x/crypto/acme"
	"golang.org/x/net/context"
	"google.golang.org/appengine"
	"google.golang.org/appengine/memcache"
	"google.golang.org/appengine/urlfetch"
)

const (
	ACMEToken = "ACME_TOKEN"
	ACMEKey   = "ACME_KEY"
	ACMEURI   = "ACME_URI"
)

func init() {
	http.HandleFunc("/", handler)
	http.HandleFunc("/auth", handleStartAuthorise)
	http.HandleFunc("/register", handleRegister)
	http.HandleFunc("/.well-known", handleChallenge)
}

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Hello, World!")
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

func handleStartAuthorise(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	key, err := getOrCreateKey(c)
	client := &acme.Client{
		Key:        key,
		HTTPClient: urlfetch.Client(c),
	}

	auth, err := client.Authorize(c, "test.clementine-player.org")
	if err != nil {
		log.Print("Failed to authorize client: ", err)
		http.Error(w, "Failed to authorize client", 500)
		return
	}

	for _, challenge := range auth.Challenges {
		if challenge.Type == "http-01" {
			log.Println("Received http challenge")
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
}

func handleChallenge(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	item, err := memcache.Get(c, "ACME_TOKEN")
	if err != nil {
		http.Error(w, "No ACME challenge in progress", 400)
		return
	}

	key, err := getOrCreateKey(c)
	if err != nil {
		http.Error(w, "Could not get key", 500)
		return
	}

	client := &acme.Client{
		Key:        key,
		HTTPClient: urlfetch.Client(c),
	}
	response, err := client.HTTP01ChallengeResponse(string(item.Value))
	if err != nil {
		http.Error(w, "Could not construct HTTP-01 challenge response", 500)
		return
	}

	io.WriteString(w, response)
}

func handleCheckStatus(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	key, err := getOrCreateKey(c)
	if err != nil {
		http.Error(w, "Could not get key", 500)
		return
	}

	item, err := memcache.Get(c, ACMEURI)
	if err != nil {
		http.Error(w, "No ACME authorisation in progress", 400)
		return
	}

	client := &acme.Client{
		Key:        key,
		HTTPClient: urlfetch.Client(c),
	}
	auth, err := client.GetAuthorization(c, string(item.Value))
	if err != nil {
		http.Error(w, "Could not get current ACME authorization", 500)
		return
	}

	io.WriteString(w, "Current status: "+auth.Status)
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	key, err := getOrCreateKey(c)
	if err != nil {
		http.Error(w, "Could not get key", 500)
		return
	}

	client := &acme.Client{
		Key:        key,
		HTTPClient: urlfetch.Client(c),
	}
	accountInfo := &acme.Account{
		Contact: []string{"mailto:john.maguire@gmail.com"},
	}

	account, err := client.Register(c, accountInfo, acme.AcceptTOS)
	if err != nil {
		log.Print("Failed to register: ", err)
		http.Error(w, "Failed to register", 500)
		return
	}

	io.WriteString(w, fmt.Sprintf("%v", account))
}
