package appengine

import (
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

func GetCurrentCreateOperations(c context.Context) ([]*CreateOperation, error) {
	var ret []*CreateOperation
	it := datastore.NewQuery(createOpKind).
		Filter("MappedCertificateID=", "").
		Order("-Accepted").
		Limit(10).
		Run(c)
	for {
		var cr CreateOperation
		switch _, err := it.Next(&cr); {
		case err == datastore.Done:
			return ret, nil
		case err != nil:
			return nil, err
		default:
			ret = append(ret, &cr)
		}
	}
}

func SetCreateOperationError(c context.Context, cr *CreateOperation, err error) error {
	if err == nil {
		return nil
	}
	cr.Error = err.Error()
	cr.Put(c)
	return err
}
