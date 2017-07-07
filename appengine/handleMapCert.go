package appengine

import (
	"fmt"

	"golang.org/x/net/context"
	"golang.org/x/oauth2/google"
	"google.golang.org/appengine"
	"google.golang.org/appengine/delay"
	"google.golang.org/appengine/log"

	aeapi "google.golang.org/api/appengine/v1beta"
)

var mapCertFunc = delay.Func("map-certificate", func(c context.Context, certID, domain string) error {
	client, err := google.DefaultClient(c, aeapi.CloudPlatformScope)
	if err != nil {
		return fmt.Errorf("Failed to create client: %v", err)
	}
	apps, err := aeapi.New(client)
	if err != nil {
		return fmt.Errorf("Failed to create appengine client: %v", err)
	}

	// Make the certificate the default for the domain.
	log.Infof(c, "Making certificate ID %s the default for domain %s", certID, domain)
	req := apps.Apps.DomainMappings.Patch(appengine.AppID(c), domain, &aeapi.DomainMapping{
		SslSettings: &aeapi.SslSettings{
			CertificateId: certID,
		},
	})
	req.UpdateMask("sslSettings.certificateId")
	if _, err := req.Do(); err != nil {
		return fmt.Errorf("Failed to map certificate: %v", err)
	}

	log.Infof(c, "Success!")
	return nil
})
