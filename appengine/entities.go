package appengine

import (
	"errors"
	"sort"
	"strconv"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/appengine/datastore"
	"google.golang.org/appengine/delay"
	"google.golang.org/appengine/log"
)

const (
	createOpKind            = "SSLCertificates-CreateOperation"
	registeredAccountKind   = "SSLCertificates-RegisteredAccount"
	registeredAccountIDName = "account"

	taskRetryCountHeader = "X-AppEngine-TaskRetryCount"
)

type RegisteredAccount struct {
	Created    time.Time
	PrivateKey []byte
	AccountID  string
	Email      string
}

type CreateOperation struct {
	HostName         string // The hostname we're creating a certificate for.
	AuthorizationURI string // ACME Authorization ID.
	ChallengeURI     string // ACME Challenge ID.
	Token            string // Challenge token.
	Response         string // Challenge response.

	Accepted  time.Time // Time we accepted the challenge.
	Responded time.Time // Time we responded to the challenge.
	Issued    time.Time // Time we were issued a certificate.
	Uploaded  time.Time // Time we upload the certificate to appengine.
	Mapped    time.Time // Time we made the certificate the default on the domain.

	Error               string
	MappedCertificateID string
	IsFinished          bool
}

func (cr *CreateOperation) Put(c context.Context) error {
	_, err := datastore.Put(c, datastore.NewKey(c, createOpKind, cr.Token, 0, nil), cr)
	return err
}

func GetCreateOperation(c context.Context, token string) (*CreateOperation, error) {
	var ret CreateOperation
	err := datastore.Get(c, datastore.NewKey(c, createOpKind, token, 0, nil), &ret)
	return &ret, err
}

func GetAllCreateOperations(c context.Context) ([]*CreateOperation, error) {
	var ret []*CreateOperation
	_, err := datastore.NewQuery(createOpKind).GetAll(c, &ret)
	return ret, err
}

// GetRecentCreateOperations returns the most recent create operations for each
// domain.  It deliberately does not use a datastore index.
func GetRecentCreateOperations(c context.Context) (map[string]*CreateOperation, error) {
	all, err := GetAllCreateOperations(c)
	if err != nil {
		return nil, err
	}
	// Sort by accepted time, ascending.
	sort.Slice(all, func(i, j int) bool { return all[i].Accepted.Before(all[j].Accepted) })

	ret := map[string]*CreateOperation{}
	for _, op := range all {
		ret[op.HostName] = op
	}
	return ret, nil
}

var (
	operationFinished = errors.New("operation finished")
)

// updateOperation runs the given function and afterwards updates the
// CreateOperation in datastore.  It sets IsFinished if the function returned
// operationFinished, or if it returned an error on its last retry.
func updateOperation(c context.Context, cr *CreateOperation, fn func() error) error {
	err := fn()
	switch {
	case err == operationFinished:
		cr.IsFinished = true
		err = nil

	case err != nil:
		cr.Error = err.Error()

		// Will we be retried again?
		r := delay.Request(c)
		retryCount, err := strconv.Atoi(r.Header.Get(taskRetryCountHeader))
		if err != nil {
			log.Warningf(c, "Failed to parse %s header %s: %v",
				taskRetryCountHeader, r.Header.Get(taskRetryCountHeader), err)
		} else {
			if retryCount == taskRetryLimit {
				log.Infof(c, "This was the last retry, marking operation as finished")
				cr.IsFinished = true
			} else {
				log.Infof(c, "This was attempt %d/%d, we should run again", retryCount, taskRetryLimit)
			}
		}
	}
	cr.Put(c)
	return err
}
