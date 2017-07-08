package appengine

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"sort"
	"strings"
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
	certs := map[string]*aeapi.AuthorizedCertificate{}
	ops := map[string]*CreateOperation{}
	var domainMappings []*aeapi.DomainMapping
	var account *RegisteredAccount
	if err := parallel.Parallel(nil, nil, func() error {
		certsResp, err := apps.AuthorizedCertificates.List(project).Do()
		if err != nil {
			return err
		}
		for _, cert := range certsResp.Certificates {
			certs[cert.Id] = cert
		}
		return nil
	}, func() error {
		domainsResp, err := apps.DomainMappings.List(project).Do()
		if err != nil {
			return err
		}
		domainMappings = domainsResp.DomainMappings
		return nil
	}, func() error {
		var err error
		_, account, err = createACMEClient(c)
		return err
	}, func() error {
		o, err := GetCurrentCreateOperations(c)
		if err != nil {
			return err
		}
		for _, op := range o {
			ops[op.HostName] = op
		}
		return nil
	}); err != nil {
		return err
	}

	// Match domains and certs and ongoing operations.
	type domainData struct {
		Name             string
		Cert             *certInfo
		OngoingOperation *CreateOperation
	}
	var domains []domainData

	usedCertIDs := map[string]struct{}{}
	for _, domain := range domainMappings {
		d := domainData{Name: domain.Id}

		// Does this domain have SSL enabled?
		if domain.SslSettings != nil {
			certID := domain.SslSettings.CertificateId
			usedCertIDs[certID] = struct{}{}

			// Find a cert with this ID.
			if cert, ok := certs[certID]; ok {
				d.Cert = makeCertInfo(cert)
			}
		}

		// Find an ongoing create operation for this domain.
		if op, ok := ops[domain.Id]; ok {
			d.OngoingOperation = op
		}

		domains = append(domains, d)
	}

	// Find unused certificates.
	var unusedCerts []*certInfo
	for id, cert := range certs {
		if _, ok := usedCertIDs[id]; !ok {
			unusedCerts = append(unusedCerts, makeCertInfo(cert))
		}
	}
	sort.Slice(unusedCerts, func(i, j int) bool {
		return strings.Compare(unusedCerts[i].ID, unusedCerts[j].ID) < 0
	})

	return tplStatus.ExecuteWriter(pongo2.Context{
		"project":     project,
		"account":     account,
		"domains":     domains,
		"unusedCerts": unusedCerts,
	}, w)
}

type certInfo struct {
	Name        string
	ID          string
	DisplayName string
	DomainNames []string
	Expiry      time.Time

	Issuer string
	Issue  time.Time
}

func makeCertInfo(raw *aeapi.AuthorizedCertificate) *certInfo {
	ret := certInfo{
		Name:        raw.Name,
		ID:          raw.Id,
		DisplayName: raw.DisplayName,
		DomainNames: raw.DomainNames,
	}
	ret.Expiry, _ = time.Parse(expireTimeFormat, raw.ExpireTime)

	// Parse the PEM to get the issuer.  We only need the first block.
	if block, _ := pem.Decode([]byte(raw.CertificateRawData.PublicCertificate)); block != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil && cert != nil {
			ret.Issuer = cert.Issuer.CommonName
			ret.Issue = cert.NotBefore
		}
	}

	return &ret
}
