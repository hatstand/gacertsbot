package appengine

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/net/context"
	"google.golang.org/appengine"
	"google.golang.org/appengine/datastore"
	"google.golang.org/appengine/delay"
	"google.golang.org/appengine/log"
	"google.golang.org/appengine/taskqueue"
	"google.golang.org/appengine/urlfetch"
	"google.golang.org/appengine/user"
)

const (
	challengePathPrefix   = "/.well-known/acme-challenge/"
	letsEncryptStagingURL = "https://acme-staging.api.letsencrypt.org/directory"

	challengeKind           = "SSLCertificates-Challenge"
	registeredAccountKind   = "SSLCertificates-RegisteredAccount"
	registeredAccountIDName = "account"
)

type RegisteredAccount struct {
	Created    time.Time
	PrivateKey []byte
	AccountID  string
}

type Challenge struct {
	AuthorizationURI string
	HostName         string

	ChallengeType string
	ChallengeURI  string
	Token         string
	Response      string

	Accepted  time.Time
	Responded time.Time

	Error string
}

func (ch *Challenge) Key(c context.Context) *datastore.Key {
	return datastore.NewKey(c, challengeKind, ch.Token, 0, nil)
}

func (ch *Challenge) Put(c context.Context) error {
	_, err := datastore.Put(c, ch.Key(c), ch)
	return err
}

func init() {
	http.HandleFunc("/ssl-certificates/auth", wrapHTTPHandler(handleStartAuthorise))
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

	hostname := r.URL.Host
	log.Infof(c, "Authorizing %s", hostname)
	auth, err := client.Authorize(c, hostname)
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
		if err := (&Challenge{
			AuthorizationURI: auth.URI,
			HostName:         hostname,
			ChallengeType:    challenge.Type,
			ChallengeURI:     challenge.URI,
			Token:            challenge.Token,
			Accepted:         time.Now(),
			Response:         response,
		}).Put(c); err != nil {
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
	var challenge Challenge
	if err := datastore.Get(c, entityKey, &challenge); err != nil {
		return err
	}

	log.Infof(c, "Responding to challenge %s with %s", challenge.ChallengeURI, challenge.Response)
	io.WriteString(w, challenge.Response)

	challenge.Responded = time.Now()
	if err := challenge.Put(c); err != nil {
		return fmt.Errorf("Failed to save updated challenge: %v", err)
	}

	return delayFunc(c, issueCertificateFunc, challenge)
}

func delayFunc(c context.Context, fn *delay.Function, args ...interface{}) error {
	task, err := fn.Task(args...)
	if err != nil {
		return fmt.Errorf("Failed to create task: %v", err)
	}

	// Ensure we run on the same module and version.
	hostname, err := appengine.ModuleHostname(c, "", "", "")
	if err != nil {
		return err
	}
	task.Header = http.Header{"Host": []string{hostname}}

	// Set some sensible retry options.
	task.RetryOptions = &taskqueue.RetryOptions{
		RetryLimit: 10,
		MinBackoff: 5 * time.Second,
		MaxBackoff: 30 * time.Second,
	}
	task.Delay = 5 * time.Second

	// Schedule the task.
	task, err = taskqueue.Add(c, task, "")
	if err != nil {
		return err
	}
	log.Infof(c, "Scheduled task %s", task.Name)
	return nil
}

var issueCertificateFunc = delay.Func("issue-certificate", func(c context.Context, ch Challenge) error {
	client, err := createACMEClient(c)
	if err != nil {
		return fmt.Errorf("Failed to create ACME client: %v", err)
	}

	// Get the status of the challenge.
	challenge, err := client.GetChallenge(c, ch.ChallengeURI)
	if err != nil {
		return fmt.Errorf("Failed to query challenge status: %v", err)
	}
	switch challenge.Status {
	case "pending":
		return fmt.Errorf("Challenge still pending, will retry later")
	case "invalid":
		log.Errorf(c, "Challenge is invalid: %v", challenge.Error)
		ch.Error = challenge.Error.Error()
		if err := ch.Put(c); err != nil {
			log.Errorf(c, "Failed to save challenge: %v", err)
		}
		return nil // Don't retry.
	}

	// Create a new key for this certificate.
	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("Failed to generate RSA private key: %v", err)
	}

	asn1Subj, _ := asn1.Marshal(pkix.Name{CommonName: ch.HostName}.ToRDNSequence())
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		RawSubject:         asn1Subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}, certKey)
	if err != nil {
		return fmt.Errorf("Failed to create CSR: %v", err)
	}

	ders, url, err := client.CreateCert(c, csr, 90*24*time.Hour, true)
	if err != nil {
		return fmt.Errorf("Failed to create certificate: %v", err)
	}
	log.Infof(c, "Got %d DER blocks for certificate %s", len(ders), url)

	for _, der := range ders {
		certs, err := x509.ParseCertificates(der)
		if err != nil {
			return fmt.Errorf("Failed to parse certificate: %v", err)
		}

		for _, cert := range certs {
			log.Infof(c, "Got cert: %v", cert)
		}
	}
	return nil
})
