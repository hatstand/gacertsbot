package appengine

import (
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/appengine/log"
)

func handleChallenge(c context.Context, w http.ResponseWriter, r *http.Request) error {
	token := strings.TrimPrefix(r.URL.Path, challengePathPrefix)

	// Find the CreateOperation in datastore.
	cr, err := GetCreateOperation(c, token)
	if err != nil {
		return err
	}

	log.Infof(c, "Responding to challenge %s with %s", cr.ChallengeURI, cr.Response)
	io.WriteString(w, cr.Response)

	cr.Responded = time.Now()
	cr.Put(c)

	return delayFunc(c, issueCertificateFunc, cr)
}
