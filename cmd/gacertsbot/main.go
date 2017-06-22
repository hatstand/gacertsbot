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
	pb "github.com/hatstand/gacertsbot/proto"
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

func main() {
	flag.Parse()

	configText, err := ioutil.ReadFile(*config)
	if err != nil {
		log.Fatal(err)
	}
	var config pb.Config
	err = proto.UnmarshalText(string(configText), &config)
	if err != nil {
		log.Fatal(err)
	}
	log.Print(config)
}
