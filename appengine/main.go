package appengine

import (
	"net/http"
)

const (
	challengePathPrefix = "/.well-known/acme-challenge/"
)

func init() {
	http.HandleFunc("/ssl-certificates/create", wrapHTTPHandler(handleCreate))
	http.HandleFunc(challengePathPrefix, wrapHTTPHandler(handleChallenge))
}
