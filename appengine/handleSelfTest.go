package appengine

import (
	"net/http"

	"golang.org/x/net/context"
	"google.golang.org/appengine/log"
)

func handleSelfTest(c context.Context, w http.ResponseWriter, r *http.Request) error {
	log.Infof(c, "Self test successful!")
	http.Error(w, "I'm a teapot!", 418)
	return nil
}
