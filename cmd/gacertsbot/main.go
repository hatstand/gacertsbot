package main

import (
	"encoding/pem"
	"flag"
	"io/ioutil"
	"log"

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
