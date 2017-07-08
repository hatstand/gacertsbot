package appengine

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/oauth2/google"
	"google.golang.org/appengine"
	"google.golang.org/appengine/delay"
	"google.golang.org/appengine/log"

	aeapi "google.golang.org/api/appengine/v1beta"
)

func createAppengineClient(c context.Context) (*aeapi.AppsService, error) {
	client, err := google.DefaultClient(c, aeapi.CloudPlatformScope)
	if err != nil {
		return nil, fmt.Errorf("Failed to create client: %v", err)
	}
	apps, err := aeapi.New(client)
	if err != nil {
		return nil, err
	}
	return apps.Apps, err
}

var uploadCertFunc = delay.Func("upload-certificate",
	func(c context.Context, cr *CreateOperation, key []byte, chain [][]byte) error {
		apps, err := createAppengineClient(c)
		if err != nil {
			return SetCreateOperationError(c, cr, fmt.Errorf("Failed to create appengine client: %v", err))
		}

		// The first certificate in the chain is ours.  Use it to make a display name.
		certs, err := x509.ParseCertificates(chain[0])
		if err != nil {
			return SetCreateOperationError(c, cr, fmt.Errorf("Failed to parse certificate: %v", err))
		}

		displayName := fmt.Sprintf("cert-%s-%x",
			strings.Replace(certs[0].Subject.CommonName, ".", "-", -1),
			certs[0].SerialNumber)

		// PEM-encode both the private key and the certificate chain.
		keyPEM, err := pemEncode(privateKeyPEMType, [][]byte{key})
		if err != nil {
			return SetCreateOperationError(c, cr, fmt.Errorf("Failed to PEM-encode private key: %v", err))
		}
		certPEM, err := pemEncode(certificatePEMType, chain)
		if err != nil {
			return SetCreateOperationError(c, cr, fmt.Errorf("Failed to PEM-encode certificates: %v", err))
		}

		// Upload the certificate.
		log.Infof(c, "Uploading certificate %s", displayName)
		log.Debugf(c, "%s\n%s", keyPEM, certPEM)
		resp, err := apps.AuthorizedCertificates.Create(appengine.AppID(c), &aeapi.AuthorizedCertificate{
			CertificateRawData: &aeapi.CertificateRawData{
				PublicCertificate: string(certPEM),
				PrivateKey:        string(keyPEM),
			},
			DisplayName: displayName,
		}).Do()
		if err != nil {
			return SetCreateOperationError(c, cr, fmt.Errorf("Failed to upload certificate: %v", err))
		}
		log.Infof(c, "Successfully uploaded %s", resp.Name)

		cr.Uploaded = time.Now()
		cr.Put(c)

		return SetCreateOperationError(c, cr, delayFunc(c, mapCertFunc, cr, resp.Id, certs[0].Subject.CommonName))
	})
