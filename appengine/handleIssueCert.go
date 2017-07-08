package appengine

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/appengine/delay"
	"google.golang.org/appengine/log"
)

var issueCertificateFunc = delay.Func("issue-certificate", func(c context.Context, cr *CreateOperation) error {
	client, _, err := createACMEClient(c)
	if err != nil {
		return SetCreateOperationError(c, cr, fmt.Errorf("Failed to create ACME client: %v", err))
	}

	// Get the status of the challenge.
	challenge, err := client.GetChallenge(c, cr.ChallengeURI)
	if err != nil {
		return SetCreateOperationError(c, cr, fmt.Errorf("Failed to query challenge status: %v", err))
	}
	switch challenge.Status {
	case "pending":
		return SetCreateOperationError(c, cr, fmt.Errorf("Challenge still pending, will retry later"))
	case "invalid":
		SetCreateOperationError(c, cr, fmt.Errorf("Challenge is invalid: %v", challenge.Error))
		return nil // Don't retry.
	}

	// Create a new key for this certificate.
	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("Failed to generate RSA private key: %v", err)
	}

	// Create the CSR.
	asn1Subj, _ := asn1.Marshal(pkix.Name{CommonName: cr.HostName}.ToRDNSequence())
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		RawSubject:         asn1Subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}, certKey)
	if err != nil {
		return SetCreateOperationError(c, cr, fmt.Errorf("Failed to create CSR: %v", err))
	}

	// Try to issue a certificate with it.
	chain, url, err := client.CreateCert(c, csr, 90*24*time.Hour, true)
	if err != nil {
		return SetCreateOperationError(c, cr, fmt.Errorf("Failed to create certificate: %v", err))
	}
	log.Infof(c, "Got %d DER blocks for certificate %s", len(chain), url)

	cr.Issued = time.Now()
	cr.Put(c)

	// Upload it to the cloud console.
	return SetCreateOperationError(c, cr, delayFunc(c, uploadCertFunc, cr, serializeKey(certKey), chain))
})
