package appengine

import (
	"fmt"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/appengine"
	"google.golang.org/appengine/delay"
	"google.golang.org/appengine/log"

	aeapi "google.golang.org/api/appengine/v1beta"
)

var mapCertFunc = delay.Func("map-certificate",
	func(c context.Context, cr *CreateOperation, certID, domain string) error {
		return updateOperation(c, cr, func() error {
			apps, err := createAppengineClient(c)
			if err != nil {
				return fmt.Errorf("Failed to create appengine client: %v", err)
			}

			// Make the certificate the default for the domain.
			log.Infof(c, "Making certificate ID %s the default for domain %s", certID, domain)
			req := apps.DomainMappings.Patch(appengine.AppID(c), domain, &aeapi.DomainMapping{
				SslSettings: &aeapi.SslSettings{
					CertificateId: certID,
				},
			})
			req.UpdateMask("sslSettings.certificateId")
			if _, err := req.Do(); err != nil {
				return fmt.Errorf("Failed to map certificate: %v", err)
			}

			cr.Mapped = time.Now()
			cr.MappedCertificateID = certID

			log.Infof(c, "Success!")
			return operationFinished
		})
	})
