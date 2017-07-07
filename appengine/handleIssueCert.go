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

var issueCertificateFunc = delay.Func("issue-certificate", func(c context.Context, ch *Challenge) error {
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

	// Create the CSR.
	asn1Subj, _ := asn1.Marshal(pkix.Name{CommonName: ch.HostName}.ToRDNSequence())
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		RawSubject:         asn1Subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}, certKey)
	if err != nil {
		return fmt.Errorf("Failed to create CSR: %v", err)
	}

	// Try to issue a certificate with it.
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
			log.Infof(c, "Got cert %s: CN=%s Issuer=%s",
				cert.SerialNumber, cert.Subject.CommonName, cert.Issuer.CommonName)
		}
	}
	return nil
})
