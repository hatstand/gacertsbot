package appengine

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"github.com/davidsansome/parallel"
	"github.com/flosch/pongo2"
	"golang.org/x/net/context"
	"google.golang.org/appengine"

	aeapi "google.golang.org/api/appengine/v1beta"
)

var (
	tplStatus = pongo2.Must(pongo2.FromFile("status.html"))
)

const (
	expireTimeFormat = "2006-01-02T15:04:05Z"
)

func handleStatus(c context.Context, w http.ResponseWriter, r *http.Request) error {
	apps, err := createAppengineClient(c)
	if err != nil {
		return fmt.Errorf("Failed to create appengine client: %v", err)
	}
	project := appengine.AppID(c)

	// Lookup everything we need in parallel.
	var certs []*aeapi.AuthorizedCertificate
	var domains []*aeapi.DomainMapping
	var account *RegisteredAccount
	var ops []*CreateOperation
	if err := parallel.Parallel(nil, nil, func() error {
		certsResp, err := apps.AuthorizedCertificates.List(project).Do()
		if err != nil {
			return err
		}
		certs = certsResp.Certificates
		return nil
	}, func() error {
		domainsResp, err := apps.DomainMappings.List(project).Do()
		if err != nil {
			return err
		}
		domains = domainsResp.DomainMappings
		return nil
	}, func() error {
		var err error
		_, account, err = createACMEClient(c)
		return err
	}, func() error {
		var err error
		ops, err = GetCurrentCreateOperations(c)
		return err
	}); err != nil {
		return err
	}

	// Match domains and certs.
	type domainData struct {
		DomainID    string
		CertID      string
		CertDomains []string
		CertExpiry  time.Time
		CertIssuer  string
		CreateOp    *CreateOperation
	}
	var data []domainData

	for _, domain := range domains {
		d := domainData{DomainID: domain.Id}
		if domain.SslSettings == nil {
			continue
		}
		d.CertID = domain.SslSettings.CertificateId

		// Find a cert with this ID.
		for _, cert := range certs {
			if cert.Id != d.CertID {
				continue
			}
			d.CertDomains = cert.DomainNames
			d.CertExpiry, _ = time.Parse(expireTimeFormat, cert.ExpireTime)

			// Parse the PEM to get the issuer.  We only need the first block.
			block, _ := pem.Decode([]byte(cert.CertificateRawData.PublicCertificate))
			if block != nil {
				certInfo, err := x509.ParseCertificate(block.Bytes)
				if err == nil && certInfo != nil {
					d.CertIssuer = certInfo.Issuer.CommonName
				}
			}
			break
		}

		// Find an ongoing create operation for this domain.
		for _, op := range ops {
			if op.HostName == domain.Id {
				d.CreateOp = op
				break
			}
		}

		data = append(data, d)
	}

	return tplStatus.ExecuteWriter(pongo2.Context{
		"project": project,
		"account": account,
		"domains": data,
	}, w)
}
