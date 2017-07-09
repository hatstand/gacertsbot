package appengine

import (
	"sort"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/appengine/datastore"
)

const (
	createOpKind            = "SSLCertificates-CreateOperation"
	registeredAccountKind   = "SSLCertificates-RegisteredAccount"
	registeredAccountIDName = "account"
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

// GetCurrentCreateOperations returns all create operations that have an error
// or are still ongoing.  It deliberately does not use a datastore index.
func GetCurrentCreateOperations(c context.Context) ([]*CreateOperation, error) {
	all, err := GetAllCreateOperations(c)
	if err != nil {
		return nil, err
	}
	var ret []*CreateOperation
	for _, op := range all {
		if op.MappedCertificateID == "" {
			ret = append(ret, op)
		}
	}

	sort.Slice(ret, func(i, j int) bool { return ret[i].Accepted.Before(ret[j].Accepted) })
	return ret, nil
}

func SetCreateOperationError(c context.Context, cr *CreateOperation, err error) error {
	if err == nil {
		return nil
	}
	cr.Error = err.Error()
	cr.Put(c)
	return err
}
