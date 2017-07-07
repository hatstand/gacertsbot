package appengine

import (
	"crypto/x509"
	"fmt"
	"strings"

	"golang.org/x/net/context"
	"google.golang.org/appengine"
	"google.golang.org/appengine/delay"
	"google.golang.org/appengine/log"

	aeapi "google.golang.org/api/appengine/v1beta"
)

var uploadCertFunc = delay.Func("upload-certificate", func(c context.Context, key []byte, chain [][]byte) error {
	client, err := getAuthenticatedClient(c)
	if err != nil {
		return fmt.Errorf("Failed to create authenticated HTTP client: %v", err)
	}

	apps, err := aeapi.New(client)
	if err != nil {
		return fmt.Errorf("Failed to create appengine client: %v", err)
	}

	// The first certificate in the chain is ours.  Use it to make a display name.
	certs, err := x509.ParseCertificates(chain[0])
	if err != nil {
		return fmt.Errorf("Failed to parse certificate: %v", err)
	}

	displayName := fmt.Sprintf("cert-%s-%x",
		strings.Replace(certs[0].Subject.CommonName, ".", "-", -1),
		certs[0].SerialNumber)

	// PEM-encode both the private key and the certificate chain.
	keyPEM, err := pemEncode(privateKeyPEMType, [][]byte{key})
	if err != nil {
		return fmt.Errorf("Failed to PEM-encode private key: %v", err)
	}
	certPEM, err := pemEncode(certificatePEMType, chain)
	if err != nil {
		return fmt.Errorf("Failed to PEM-encode certificates: %v", err)
	}

	// Upload the certificate.
	log.Infof(c, "Uploading certificate %s", displayName)
	log.Debugf(c, "%s\n%s", keyPEM, certPEM)
	resp, err := apps.Apps.AuthorizedCertificates.Create(appengine.AppID(c), &aeapi.AuthorizedCertificate{
		CertificateRawData: &aeapi.CertificateRawData{
			PublicCertificate: string(certPEM),
			PrivateKey:        string(keyPEM),
		},
		DisplayName: displayName,
	}).Do()
	if err != nil {
		return fmt.Errorf("Failed to upload certificate: %v", err)
	}

	log.Infof(c, "Did it work? %v", resp)
	return nil
})
