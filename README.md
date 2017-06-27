# gacertsbot
Updates SSL certificates on Google AppEngine

## Usage

```
go run cmd/gacertsbot/main.go -config config.txt -fullchain fullchain.pem -key privatekey.pem
```

`config.txt` should be a [Config proto](proto/config.proto) in text format.
`fullchain.pem` should be the public keys for your certificate in PEM format including any required certificates in the root chain.
`privatekey.pem` should be a private key file in PEM PKCS8 format, i.e. it should begin with something like === BEGIN PRIVATE KEY ===.

## Credentials

gacertsbot uses
[Google Application Default Credentials](https://developers.google.com/identity/protocols/application-default-credentials)
which are setup via the `GOOGLE_APPLICATION_CREDENTIALS` environment variable.

You probably want to create a service account with admin access to each appengine project and add that email address as a verified owner to
[Google Webmaster Central](https://www.google.com/webmasters/verification/verification) too.
