package appengine

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/appengine/datastore"
	"google.golang.org/appengine/log"
)

func handleChallenge(c context.Context, w http.ResponseWriter, r *http.Request) error {
	token := strings.TrimPrefix(r.URL.Path, challengePathPrefix)

	// Find the challenge in datastore.
	entityKey := datastore.NewKey(c, challengeKind, token, 0, nil)
	var challenge Challenge
	if err := datastore.Get(c, entityKey, &challenge); err != nil {
		return err
	}

	log.Infof(c, "Responding to challenge %s with %s", challenge.ChallengeURI, challenge.Response)
	io.WriteString(w, challenge.Response)

	challenge.Responded = time.Now()
	if err := challenge.Put(c); err != nil {
		return fmt.Errorf("Failed to save updated challenge: %v", err)
	}

	return delayFunc(c, issueCertificateFunc, challenge)
}
