package appengine

import (
	"fmt"
	"net/http"

	"golang.org/x/net/context"
	"google.golang.org/appengine"
	"google.golang.org/appengine/log"
)

func handleDelete(c context.Context, w http.ResponseWriter, r *http.Request) error {
	if r.Method != "POST" {
		return fmt.Errorf("Invalid method %s", r.Method)
	}
	certID := r.FormValue("id")
	if certID == "" {
		return fmt.Errorf("Missing id parameter")
	}

	apps, err := createAppengineClient(c)
	if err != nil {
		return fmt.Errorf("Failed to create appengine client: %v", err)
	}

	log.Infof(c, "Deleting certificate ID %s", certID)
	if _, err := apps.AuthorizedCertificates.Delete(appengine.AppID(c), certID).Do(); err != nil {
		return fmt.Errorf("Failed to delete certificate %s: %v", certID, err)
	}

	http.Redirect(w, r, "/ssl-certificates/status", http.StatusFound)
	return nil
}
