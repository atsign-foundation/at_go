package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/atsign-foundation/at_go/at_client/atclient"
	"github.com/atsign-foundation/at_go/at_client/common"
	"github.com/atsign-foundation/at_go/at_client/connections"
)

func main() {
	url := flag.String("u", "root.atsign.org:64", "root url of the server")
	atsign := flag.String("a", "", "atsign to be activated")
	verbose := flag.String("v", "false", "Verbose == true|false")
	regex := flag.String("r", "", "Scan Regex")

	flag.Parse()

	if *atsign == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	rootURL := *url
	atSign := common.NewAtSign(*atsign)
	verboseFlag := *verbose == "true"

	var atClient *atclient.AtClient
	var err error

	// Init AtClient
	what := ""
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Failed to %s %v\n", what, r)
			os.Exit(1)
		}
	}()
	what = "initialize AtClient"
	address, err := connections.AddressFromString(rootURL)
	if err != nil {
		panic(err)
	}
	atClient, err = atclient.NewAtClient(*atSign, *address, verboseFlag)
	if err != nil {
		fmt.Println(err.Error())
	}

	var atKeys []common.AtKey
	what = fmt.Sprintf("GetAtKeys(%s)", *regex)
	atKeys, err = atClient.GetAtKeys(*regex, true)
	if err != nil {
		fmt.Printf("Failed to %s - %v\n", what, err)
		os.Exit(1)
	}

	inputText := ""
	for inputText != "q" {
		fmt.Println()
		fmt.Print("Enter index you want to lookup (l to list, q to quit): ")
		fmt.Scanln(&inputText)

		if inputText == "q" {
			break
		}

		if inputText == "l" {
			_printAtKeys(atKeys)
		} else if index, err := strconv.Atoi(inputText); err == nil && index >= 0 && index < len(atKeys) {
			atKey := atKeys[index]
			_printAtKeyInfo(atKey)
		} else {
			fmt.Println("Invalid input")
		}
	}

	fmt.Println("Done")
}

func _printAtKeys(atKeys []common.AtKey) {
	fmt.Println("atKeys: {")
	for i, atKey := range atKeys {
		fmt.Printf("  %d:  %s\n", i, atKey)
	}
	fmt.Println("}")
}

func _printAtKeyInfo(atKey common.AtKey) {
	fmt.Println("======================")
	fmt.Println("Full KeyName:", atKey.GetFullyQualifiedKeyName())
	fmt.Println("KeyName:", atKey.String())
	fmt.Println("Namespace:", atKey.GetNamespace())
	// fmt.Println("SharedBy:", )
	// if atKey.SharedWith.AtSignStr != "" {
	// 	fmt.Println("SharedWith:", atKey.SharedWith.AtSignStr)
	// } else {
	// 	fmt.Println("SharedWith: nil")
	// }
	// fmt.Println("KeyType:", atKey.Type)
	fmt.Println("Metadata -------------------")
	_printMetadata(*atKey.GetMetadata())
	fmt.Println("======================")
	fmt.Println()
}

func _printMetadata(metadata common.Metadata) {
	fmt.Println("ttl:", metadata.TTL)
	fmt.Println("ttb:", metadata.TTB)
	fmt.Println("ttr:", metadata.TTR)
	fmt.Println("ccd:", metadata.CCD)
	if metadata.AvailableAt != nil {
		fmt.Println("availableAt:", metadata.AvailableAt.String())
	} else {
		fmt.Println("availableAt: null")
	}
	if metadata.ExpiresAt != nil {
		fmt.Println("expiresAt:", metadata.ExpiresAt.String())
	} else {
		fmt.Println("expiresAt: null")
	}
	if metadata.RefreshAt != nil {
		fmt.Println("refreshAt:", metadata.RefreshAt.String())
	} else {
		fmt.Println("refreshAt: null")
	}
	if metadata.CreatedAt != nil {
		fmt.Println("createdAt:", metadata.CreatedAt.String())
	} else {
		fmt.Println("createdAt: null")
	}
	if metadata.UpdatedAt != nil {
		fmt.Println("updatedAt:", metadata.UpdatedAt.String())
	} else {
		fmt.Println("updatedAt: null")
	}
	fmt.Println("dataSignature:", metadata.DataSignature)
	fmt.Println("sharedKeyStatus:", metadata.SharedKeyStatus)
	fmt.Println("isPublic:", metadata.IsPublic)
	fmt.Println("isEncrypted:", metadata.IsEncrypted)
	fmt.Println("isHidden:", metadata.IsHidden)
	fmt.Println("namespaceAware:", metadata.NamespaceAware)
	fmt.Println("isBinary:", metadata.IsBinary)
	fmt.Println("isCached:", metadata.IsCached)
	fmt.Println("sharedKeyEnc:", metadata.SharedKeyEnc)
	fmt.Println("pubKeyCS:", metadata.PubKeyCS)
	fmt.Println("ivNonce:", metadata.IVNonce)
}
