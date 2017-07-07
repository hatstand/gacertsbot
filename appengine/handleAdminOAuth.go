package appengine

import (
	"fmt"
	"net/http"
	"net/url"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/appengine/datastore"
	"google.golang.org/appengine/log"

	aeapi "google.golang.org/api/appengine/v1beta"
)

const (
	// TODO: make these configurable.
	clientID     = "912024436378-g9kcu4k7gjk85vbk28i5nb4b0c321vgj.apps.googleusercontent.com"
	clientSecret = "BtZucqugQsF0d7PxRg64VmeG"
)

func createOAuthConfig(u *url.URL) *oauth2.Config {
	redirectURL := *u
	redirectURL.Path = "/ssl-certificates/oauth-login"
	redirectURL.RawQuery = ""
	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     google.Endpoint,
		RedirectURL:  redirectURL.String(),
		Scopes:       []string{aeapi.CloudPlatformScope},
	}
}

func handleOAuthLogin(c context.Context, w http.ResponseWriter, r *http.Request) error {
	admin, err := GetAdminCredentials(c)
	if err != nil {
		return fmt.Errorf("Failed to get admin credentials: %v", err)
	}

	code := r.FormValue("code")
	state := r.FormValue("state")
	if code == "" || state == "" {
		return fmt.Errorf("Missing URL parameters")
	}
	if state != admin.State {
		return fmt.Errorf("State mismatch")
	}

	config := createOAuthConfig(r.URL)
	tok, err := config.Exchange(c, code)
	if err != nil {
		return fmt.Errorf("Failed to exchange oauth token: %v", err)
	}

	admin.Token = *tok
	if err := admin.Put(c); err != nil {
		return fmt.Errorf("Failed to store admin credentials: %v", err)
	}

	redirectURL := *r.URL
	redirectURL.Path = "/ssl-certificates/create"
	redirectURL.RawQuery = ""
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
	return nil
}

func hasAdminCredentials(c context.Context, w http.ResponseWriter, r *http.Request) (bool, error) {
	// Do we already have an administrator's credentials?
	admin, err := GetAdminCredentials(c)
	if err != nil && err != datastore.ErrNoSuchEntity {
		return false, fmt.Errorf("Failed to get admin credentials: %v", err)
	}

	// Already logged in.
	if admin.Token.Valid() {
		log.Infof(c, "Found valid admin credential")
		return true, nil
	}

	// Not logged in yet.  Start 3-legged auth flow.s
	log.Infof(c, "No valid admin credential, starting auth flow")
	state := randomString(64)
	admin.State = state
	if err := admin.Put(c); err != nil {
		return false, fmt.Errorf("Failed to store admin credentials: %v", err)
	}

	config := createOAuthConfig(r.URL)
	http.Redirect(w, r, config.AuthCodeURL(state), http.StatusFound)
	return false, nil
}

func getAuthenticatedClient(c context.Context) (*http.Client, error) {
	admin, err := GetAdminCredentials(c)
	if err != nil {
		return nil, fmt.Errorf("Failed to get admin credentials: %v", err)
	}

	config := createOAuthConfig(&url.URL{})
	return config.Client(c, &admin.Token), nil
}
