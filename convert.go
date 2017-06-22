package gacertsbot

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

const (
	PKCS8_HEADER = "PRIVATE KEY"
	PKCS1_HEADER = "RSA PRIVATE KEY"
)

func PKCS8ToPKCS1(pkcs8 []byte) ([]byte, error) {
	block, _ := pem.Decode(pkcs8)
	if block == nil || block.Type != PKCS8_HEADER {
		return nil, errors.New("Failed to decode private key block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("Failed to decode private key")
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("Failed to extract RSA key")
	}

	pkcs1 := x509.MarshalPKCS1PrivateKey(rsaKey)

	return pem.EncodeToMemory(&pem.Block{
		Type:  PKCS1_HEADER,
		Bytes: pkcs1,
	}), nil
}
