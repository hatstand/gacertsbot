package appengine

import (
	"fmt"
	"net/http"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/appengine/log"
)

func handleCreate(c context.Context, w http.ResponseWriter, r *http.Request) error {
	switch ok, err := hasAdminCredentials(c, w, r); {
	case err != nil:
		return err
	case ok == false:
		return nil
	}

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

		log.Infof(c, "Received http challenge (%s) %s, token %s",
			challenge.Status, challenge.URI, challenge.Token)

		// Get a response ready.
		response, err := client.HTTP01ChallengeResponse(challenge.Token)
		if err != nil {
			return fmt.Errorf("Failed to create response to %s: %v", challenge.Token, err)
		}

		ch := &Challenge{
			AuthorizationURI: auth.URI,
			HostName:         hostname,
			ChallengeType:    challenge.Type,
			ChallengeURI:     challenge.URI,
			Token:            challenge.Token,
			Accepted:         time.Now(),
			Response:         response,
		}
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

		switch challenge.Status {
		case "valid":
			// We've already authorized this domain, skip straight to requesting
			// another certificate.
			// Get the existing one from datastore if we can.
			log.Infof(c, "Challenge is already valid, getting certificate")
			if existingCh, err := GetChallenge(c, challenge.Token); err == nil {
				ch = existingCh
			}
			return delayFunc(c, issueCertificateFunc, ch)

		default:
			// Accept the challenge.
			if _, err := client.Accept(c, challenge); err != nil {
				return fmt.Errorf("Failed to accept challenge: %v", err)
			}
			log.Infof(c, "Accepted challenge")
		}
		break
	}
	return nil
}
