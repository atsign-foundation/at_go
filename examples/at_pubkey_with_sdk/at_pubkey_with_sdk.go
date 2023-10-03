package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/atsign-foundation/at_go/at_client/atclient"
	"github.com/atsign-foundation/at_go/at_client/common"
	"github.com/atsign-foundation/at_go/at_client/connections"
)

func main() {
	args := os.Args
	port := flag.String("port", "64", "port to connect")
	atsign := flag.String("atsign", args[1], "atSign to query")
	flag.Parse()

	address, err := connections.AddressFromString("root.atsign.org:" + *port)
	if err != nil {
		panic(err)
	}

	atClient, err := atclient.NewAtClient(*common.NewAtSign(*atsign), *address, true)
	if err != nil {
		fmt.Println(err.Error())
	}

	response, err := atClient.SecondaryConnection.AtConnection.ExecuteCommand("llookup:public:publickey@"+*atsign, true)
	if err != nil {
		panic(err)
	}

	parsedResponse, err := connections.ParseRawResponse(response.GetRawDataResponse())
	if err != nil {
		panic(err)
	} else {
		fmt.Println("atServer public key:", parsedResponse.GetRawDataResponse())
	}
}
