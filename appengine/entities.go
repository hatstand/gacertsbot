package appengine

import (
	"time"

	"golang.org/x/net/context"
	"google.golang.org/appengine/datastore"
)

const (
	challengeKind           = "SSLCertificates-Challenge"
	registeredAccountKind   = "SSLCertificates-RegisteredAccount"
	registeredAccountIDName = "account"
)

type RegisteredAccount struct {
	Created    time.Time
	PrivateKey []byte
	AccountID  string
}

type Challenge struct {
	AuthorizationURI string
	HostName         string

	ChallengeType string
	ChallengeURI  string
	Token         string
	Response      string

	Accepted  time.Time
	Responded time.Time

	Error string
}

func (ch *Challenge) Put(c context.Context) error {
	_, err := datastore.Put(c, datastore.NewKey(c, challengeKind, ch.Token, 0, nil), ch)
	return err
}

func GetChallenge(c context.Context, token string) (*Challenge, error) {
	var ret Challenge
	err := datastore.Get(c, datastore.NewKey(c, challengeKind, token, 0, nil), &ret)
	return &ret, err
}
