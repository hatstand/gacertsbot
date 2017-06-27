package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/hatstand/gacertsbot"
	pb "github.com/hatstand/gacertsbot/proto"
	"golang.org/x/net/context"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/appengine/v1beta"
)

var fullchain = flag.String("fullchain", "", "Path to PEM-encoded full certificate chain")
var key = flag.String("key", "", "Path to PEM-encoded PKCS8 key")
var config = flag.String("config", "", "Path to text proto config file")

func extractBlocks(data []byte) []*pem.Block {
	block, rest := pem.Decode(data)
	if block == nil {
		return []*pem.Block{}
	}
	return append(extractBlocks(rest), block)
}

func extractExpiry(chain []byte, domain string) (time.Time, error) {
	blocks := extractBlocks(chain)
	for _, block := range blocks {
		certs, err := x509.ParseCertificates(block.Bytes)
		if err != nil {
			return time.Unix(0, 0), fmt.Errorf("Failed to parse certificates: %v", err)
		}

		for _, cert := range certs {
			for _, name := range cert.DNSNames {
				if strings.Contains(name, domain) {
					return cert.NotAfter, nil
				}
			}
		}
	}
	return time.Unix(0, 0), fmt.Errorf("Could not find domain %s in certificates", domain)
}

func extractExpiryFromConfig(chain []byte, config *pb.Config) (time.Time, error) {
	for _, project := range config.Project {
		for _, domain := range project.Domain {
			expiry, err := extractExpiry(chain, domain)
			if err != nil {
				return expiry, nil
			}
		}
	}
	return time.Unix(0, 0), fmt.Errorf("Could not find a matching domain from the config in the certificate")
}

func buildCert(fullchain []byte, privateKey []byte, config *pb.Config) (*appengine.AuthorizedCertificate, error) {
	rsaKey, err := gacertsbot.PKCS8ToPKCS1(privateKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to convert key to PKCS1: %v", err)
	}

	expiry, err := extractExpiryFromConfig(fullchain, config)
	if err != nil {
		return nil, fmt.Errorf("Failed to extract expiry from certificate: %v", err)
	}

	cert := &appengine.AuthorizedCertificate{
		CertificateRawData: &appengine.CertificateRawData{
			PublicCertificate: string(fullchain),
			PrivateKey:        string(rsaKey),
		},
		DisplayName: fmt.Sprintf("cert-%02d-%d", expiry.Month(), expiry.Year()),
	}
	return cert, nil
}

func uploadCert(project string, cert *appengine.AuthorizedCertificate) (string, error) {
	client, err := google.DefaultClient(context.Background(), appengine.CloudPlatformScope)
	if err != nil {
		return "", fmt.Errorf("Failed to create client: %v", err)
	}
	apps, err := appengine.New(client)
	if err != nil {
		return "", fmt.Errorf("Failed to create appengine client: %v", err)
	}

	resp, err := apps.Apps.AuthorizedCertificates.Create(project, cert).Do()
	if err != nil {
		return "", fmt.Errorf("Failed to upload certificate: %v", err)
	}
	return resp.Id, nil
}

func mapDomainToCertificate(project string, domain string, certId string) error {
	client, err := google.DefaultClient(context.Background(), appengine.CloudPlatformScope)
	if err != nil {
		return fmt.Errorf("Failed to create client: %v", err)
	}
	apps, err := appengine.New(client)
	if err != nil {
		return fmt.Errorf("Failed to create appengine client: %v", err)
	}

	req := apps.Apps.DomainMappings.Patch(project, domain, &appengine.DomainMapping{
		SslSettings: &appengine.SslSettings{
			CertificateId: certId,
		},
	})
	req.UpdateMask("sslSettings.certificateId")
	_, err = req.Do()
	if err != nil {
		return fmt.Errorf("Failed to map certificate for project: %s domain: %s: %v", project, domain, err)
	}
	return nil
}

func main() {
	flag.Parse()

	configText, err := ioutil.ReadFile(*config)
	if err != nil {
		log.Fatalf("Failed to read config from %s: %v", *config, err)
	}
	var config pb.Config
	err = proto.UnmarshalText(string(configText), &config)
	if err != nil {
		log.Fatal("Failed to parse config: ", err)
	}

	publicKeyChain, err := ioutil.ReadFile(*fullchain)
	if err != nil {
		log.Fatalf("Failed to read public key from %s: %v", *fullchain, err)
	}

	privateKey, err := ioutil.ReadFile(*key)
	if err != nil {
		log.Fatalf("Failed to read private key from: %s %v", *key, err)
	}

	cert, err := buildCert(publicKeyChain, privateKey, &config)
	if err != nil {
		log.Fatal("Failed to build certificate: ", err)
	}

	certId, err := uploadCert(*config.Project[0].ProjectId, cert)
	if err != nil {
		log.Fatal("Failed to upload certificate to appengine: ", err)
	}

	for _, project := range config.Project {
		for _, domain := range project.Domain {
			err := mapDomainToCertificate(*project.ProjectId, domain, certId)
			if err != nil {
				log.Printf("Failed to map cert for domain: %v", err)
			}
		}
	}
}
