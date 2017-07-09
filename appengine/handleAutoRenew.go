package appengine

import (
	"fmt"
	"net/http"
	"time"

	"github.com/davidsansome/parallel"
	"golang.org/x/net/context"
	"google.golang.org/appengine"
	"google.golang.org/appengine/log"

	aeapi "google.golang.org/api/appengine/v1beta"
)

var (
	autoRenewCertPeriod = 30 * 24 * time.Hour // 30 days
)

func handleAutoRenew(c context.Context, w http.ResponseWriter, r *http.Request) error {
	apps, err := createAppengineClient(c)
	if err != nil {
		return fmt.Errorf("Failed to create appengine client: %v", err)
	}
	project := appengine.AppID(c)

	// Get domains and certificates in parallel.
	certs := map[string]*aeapi.AuthorizedCertificate{}
	var domainMappings []*aeapi.DomainMapping
	if err := parallel.Parallel(nil, nil, func() error {
		resp, err := apps.AuthorizedCertificates.List(project).Do()
		if err != nil {
			return err
		}
		for _, cert := range resp.Certificates {
			certs[cert.Id] = cert
		}
		return nil
	}, func() error {
		resp, err := apps.DomainMappings.List(project).Do()
		if err != nil {
			return err
		}
		domainMappings = resp.DomainMappings
		return nil
	}); err != nil {
		return err
	}

	// Renew any certificates that will expire soon.
	for _, domain := range domainMappings {
		if domain.SslSettings == nil {
			continue
		}

		cert, ok := certs[domain.SslSettings.CertificateId]
		if !ok {
			log.Warningf(c, "Couldn't find certificate %s for %s", domain.SslSettings.CertificateId, domain.Id)
			continue
		}

		expiry, err := time.Parse(expireTimeFormat, cert.ExpireTime)
		if err != nil {
			log.Warningf(c, "Couldn't parse expiry time '%s' for %s, skipping domain", cert.ExpireTime, domain.Id)
			continue
		}

		if time.Now().Add(autoRenewCertPeriod).After(expiry) {
			log.Infof(c, "Cert for %s expires on %s, renewing now", domain.Id, expiry.String())
			if err := delayFunc(c, createFunc, domain.Id); err != nil {
				log.Errorf(c, "Failed to schedule auto-renew for %s: %v", domain.Id, err)
				// Continue anyway.
			}
		} else {
			log.Infof(c, "Not renewing %s - cert expires on %s", domain.Id, expiry.String())
		}
	}

	return nil
}
