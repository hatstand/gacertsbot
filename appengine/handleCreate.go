package appengine

import (
	"fmt"
	"net/http"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/appengine/log"
)

func handleCreate(c context.Context, w http.ResponseWriter, r *http.Request) error {
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

		log.Infof(c, "Received http challenge %s, token %s", challenge.URI, challenge.Token)

		// Get a response ready.
		response, err := client.HTTP01ChallengeResponse(challenge.Token)
		if err != nil {
			return fmt.Errorf("Failed to create response to %s: %v", challenge.Token, err)
		}

		// Accept the challenge.
		challenge, err := client.Accept(c, challenge)
		if err != nil {
			return fmt.Errorf("Failed to accept challenge: %v", err)
		}
		log.Infof(c, "Accepted challenge")

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
		break
	}
	return nil
}
