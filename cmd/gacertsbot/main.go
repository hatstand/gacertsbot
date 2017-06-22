package main

import (
	"flag"
	"io/ioutil"
	"log"

	"github.com/golang/protobuf/proto"
	pb "github.com/hatstand/gacertsbot/proto"
)

var fullchain = flag.String("fullchain", "", "Path to PEM-encoded full certificate chain")
var key = flag.String("key", "", "Path to PEM-encoded PKCS8 key")
var config = flag.String("config", "", "Path to text proto config file")

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
