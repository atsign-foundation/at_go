package atclient

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/atsign-foundation/at_go/at_client/common"
	"github.com/atsign-foundation/at_go/at_client/connections"
	"github.com/atsign-foundation/at_go/at_client/exceptions"
	"github.com/atsign-foundation/at_go/at_client/utils/auth_util"
	"github.com/atsign-foundation/at_go/at_client/utils/encryption_util"
	"github.com/atsign-foundation/at_go/at_client/utils/key_utils"
	"github.com/atsign-foundation/at_go/at_client/utils/verb_builder"
)

type AtClient struct {
	AtSign              common.AtSign
	SecondaryAddress    connections.Address
	SecondaryConnection connections.AtSecondaryConnection
	Keys                map[string]string
	Verbose             bool
	Authenticated       bool
}

func NewAtClient(atsign common.AtSign, address connections.Address, verbose bool) (*AtClient, error) {
	ku := &key_utils.KeysUtil{}
	keysMap, err := ku.LoadKeys(atsign.AtSignStr)
	if err != nil {
		return nil, err
	}

	secondaryAddress := connections.NewAddress("", 0)

	client := &AtClient{
		AtSign:  atsign,
		Keys:    keysMap,
		Verbose: verbose,
	}

	if secondaryAddress.String() == ":0" {
		rootConnection := connections.GetAtRootConnectionInstance()
		address, exception := rootConnection.FindSecondary(atsign)
		if exception != nil {
			return nil, exception
		}
		secondaryAddress = address
	}
	client.SecondaryAddress = *secondaryAddress
	client.SecondaryConnection = *connections.NewAtSecondaryConnection(*secondaryAddress, verbose)
	var authErr = auth_util.AuthenticateWithPkam(*client.SecondaryConnection.AtConnection, client.AtSign, keysMap)
	if authErr != nil {
		fmt.Println(authErr)
	}

	client.Authenticated = true
	return client, nil
}

func (c *AtClient) GetAtKeys(regex string, fetchMetadata bool) ([]common.AtKey, error) {
	scanCommand := verb_builder.NewScanVerbBuilder().SetRegex(regex).SetShowHidden(false).Build()
	scanRawResponse, err := c.SecondaryConnection.AtConnection.ExecuteCommand(scanCommand, true)
	if err != nil {
		return nil, fmt.Errorf("Failed to execute : %s : %s", scanCommand, err)
	}
	scanRawResponse, err = connections.ParseRawResponse(scanRawResponse.GetRawDataResponse())
	if err != nil {
		return nil, fmt.Errorf("Failed to format raw response: " + err.Error())
	}

	keysList := []string{}
	if len(scanRawResponse.GetRawDataResponse()) > 0 {
		jsonData := strings.Replace(scanRawResponse.GetRawDataResponse(), "data:", "", 1)
		err := json.Unmarshal([]byte(jsonData), &keysList)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse JSON : %s : %s", jsonData, err)
		}
	}

	atKeys := []common.AtKey{}
	for _, atKeyRaw := range keysList {
		atKey, err := common.KeysFromString(atKeyRaw)
		if err != nil {
			return atKeys, err
		}
		if fetchMetadata {
			llookupCommand := "llookup:meta:" + atKeyRaw
			llookupMetaResponse, err := c.SecondaryConnection.AtConnection.ExecuteCommand(llookupCommand, true)
			if err != nil {
				return nil, fmt.Errorf("Failed to execute : %s : %s", llookupCommand, err)
			}
			formattedLlookupMetaResponse, err := connections.ParseRawResponse(llookupMetaResponse.GetRawDataResponse())
			if err != nil {
				return nil, err
			}
			metadata, err := common.FromJSON(formattedLlookupMetaResponse.GetRawDataResponse())
			if err != nil {
				return nil, err
			}
			atKey.SetMetadata(*metadata)
		}

		atKeys = append(atKeys, atKey)
	}

	return atKeys, nil
}

func (c *AtClient) IsAuthenticated() bool {
	return c.Authenticated
}

func (c *AtClient) GetPublicEncryptionKey(sharedWith common.AtSign) (string, error) {
	command := "plookup:publickey" + sharedWith.AtSignStr
	response, err := c.SecondaryConnection.AtConnection.ExecuteCommand(command, true)
	if err != nil {
		return "", err
	}
	if response.IsError() {
		return response.GetErrorText(), response.GetException()
	} else {
		return response.GetRawDataResponse(), nil
	}
}

func (c *AtClient) CreateSharedEncryptionKey(sharedKey common.SharedKey) (string, error) {
	theirPubEncKey, err := c.GetPublicEncryptionKey(*sharedKey.SharedWith)
	if err != nil {
		return "", err
	}

	var aesKey = ""
	var encUtil = encryption_util.NewEncryptionUtil()

	aesKey, err = encUtil.GenerateAESKeyBase64()
	if err != nil {
		return "", err
	}

	var step = ""

	step = "encrypt new shared key with their public key"
	encryptedForOther, err := encUtil.RsaEncryptToBase64(aesKey, []byte(theirPubEncKey))
	if err != nil {
		return "", exceptions.NewAtEncryptionException("Failed to " + step + " - " + err.Error())
	}

	step = "encrypt new shared key with our public key"
	encryptedForUs, err := encUtil.RsaEncryptToBase64(aesKey, []byte(c.Keys[key_utils.EncryptionPublicKeyName]))
	if err != nil {
		return "", exceptions.NewAtEncryptionException("Failed to " + step + " - " + err.Error())
	}

	step = "save encrypted shared key for us"
	command1 := "update:" + "shared_key." + sharedKey.SharedWith.WithoutPrefix + sharedKey.SharedBy.AtSignStr +
		" " + encryptedForUs
	c.SecondaryConnection.AtConnection.ExecuteCommand(command1, true)

	step = "save encrypted shared key for them"
	ttr := 24 * 60 * 60 * 1000
	command2 := "update:ttr:" + strconv.Itoa(ttr) + ":" + sharedKey.SharedWith.AtSignStr + ":shared_key" + sharedKey.SharedBy.AtSignStr +
		" " + encryptedForOther
	c.SecondaryConnection.AtConnection.ExecuteCommand(command2, true)

	return aesKey, nil
}

func (c *AtClient) GetEncryptionKeySharedByMe(key common.SharedKey) (string, error) {
	toLookup := "shared_key." + key.SharedWith.WithoutPrefix + c.AtSign.AtSignStr
	command := "llookup:" + toLookup

	response, err := c.SecondaryConnection.AtConnection.ExecuteCommand(command, true)
	if err != nil {
		return "", err
	}

	if response.IsError() {
		if _, ok := response.GetException().(exceptions.AtKeyNotFoundException); ok {
			return c.CreateSharedEncryptionKey(key)
		} else {
			panic(response.GetException())
		}
	}

	result, err := encryption_util.NewEncryptionUtil().RsaDecryptFromBase64(
		response.GetRawDataResponse(),
		[]byte(c.Keys[key_utils.EncryptionPrivateKeyName]))

	if err != nil {
		return "", exceptions.NewAtDecryptionException(err.Error())
	} else {
		return result, nil
	}
}

func (c *AtClient) GetEncryptionKeySharedByOther(key common.SharedKey) (string, error) {
	sharedSharedKeyName := key.GetSharedSharedKeyName()

	sharedKeyValue := c.Keys[sharedSharedKeyName]
	if sharedKeyValue != "" {
		return sharedKeyValue, nil
	}

	lookupCommand := "lookup:" + "shared_key" + key.SharedBy.AtSignStr
	rawResponse, err := c.SecondaryConnection.AtConnection.ExecuteCommand(lookupCommand, true)
	if err != nil {
		if err == exceptions.NewAtKeyNotFoundException(err.Error()) {
			return "", exceptions.NewAtKeyNotFoundException(err.Error())
		} else {
			return "", exceptions.NewAtSecondaryConnectException("Failed to execute " + lookupCommand + " - " + err.Error())
		}
	}

	sharedSharedKeyDecryptedValue, err := encryption_util.NewEncryptionUtil().RsaDecryptFromBase64(
		rawResponse.GetRawDataResponse(),
		[]byte(c.Keys[key_utils.EncryptionPrivateKeyName]))
	if err != nil {
		return "", exceptions.NewAtDecryptionException("Failed to decrypt the shared_key with our encryption private key - " + err.Error())
	}

	c.Keys[sharedSharedKeyName] = sharedSharedKeyDecryptedValue
	return sharedSharedKeyDecryptedValue, nil
}

func (c *AtClient) Put(key common.AtKey, value string) (*connections.Response, error) {
	switch k := key.(type) {
	case *common.SelfKey:
		return c.putSelfKey(*k, value)
	case *common.PublicKey:
		return c.putPublicKey(*k, value)
	case *common.SharedKey:
		return c.putSharedKey(*k, value)
	}
	return nil, exceptions.NewAtException("No implementation found for key type: " + reflect.TypeOf(key).Name())
}

func (c *AtClient) putSelfKey(key common.SelfKey, value string) (*connections.Response, error) {
	signature, err := encryption_util.NewEncryptionUtil().SignSHA256RSA(value, []byte(c.Keys[key_utils.EncryptionPrivateKeyName]))
	if err != nil {
		return nil, err
	}

	key.Metadata.DataSignature = signature

	ciphertext, err := encryption_util.NewEncryptionUtil().AesEncryptFromBase64(value, c.Keys[key_utils.SelfEncryptionKeyName], []byte(key.Metadata.IVNonce))
	if err != nil {
		return nil, exceptions.NewAtEncryptionException("Failed to encrypt value with self encryption key - " + err.Error())
	}

	command := verb_builder.NewUpdateVerbBuilder().WithAtKey(&key.AtKeyBase, ciphertext).Build()

	response, err := c.SecondaryConnection.AtConnection.ExecuteCommand(command, true)
	if err != nil {
		return nil, exceptions.NewAtSecondaryConnectException("Failed to execute {command} - " + command)
	}

	return response, nil
}

func (c *AtClient) putPublicKey(key common.PublicKey, value string) (*connections.Response, error) {
	signature, err := encryption_util.NewEncryptionUtil().SignSHA256RSA(value, []byte(c.Keys[key_utils.EncryptionPrivateKeyName]))
	if err != nil {
		return nil, err
	}

	key.Metadata.DataSignature = signature
	command := verb_builder.NewUpdateVerbBuilder().WithAtKey(&key.AtKeyBase, value).Build()

	response, err := c.SecondaryConnection.AtConnection.ExecuteCommand(command, true)
	if err != nil {
		return nil, exceptions.NewAtSecondaryConnectException("Failed to execute {command} - " + command)
	}

	return response, nil
}

func (c *AtClient) putSharedKey(key common.SharedKey, value string) (*connections.Response, error) {
	if c.AtSign != *key.SharedBy {
		return nil, exceptions.NewAtIllegalArgumentException("sharedBy is " + key.SharedBy.AtSignStr + " but should be this client's atSign " + c.AtSign.AtSignStr)
	}

	var what = "fetch/create shared encryption key"
	sharedToEncryptionKey, err := c.GetEncryptionKeySharedByMe(key)
	if err != nil {
		return nil, exceptions.NewAtEncryptionException("Failed to " + what + " - " + err.Error())
	}

	what = "encrypt value with shared encryption key"
	ciphertext, err := encryption_util.NewEncryptionUtil().AesEncryptFromBase64(value, sharedToEncryptionKey, []byte(key.Metadata.IVNonce))
	if err != nil {
		return nil, exceptions.NewAtEncryptionException("Failed to " + what + " - " + err.Error())
	}
	metadataStr := key.Metadata.String()
	command := fmt.Sprintf("update%s:%s %s", metadataStr, key.String(), ciphertext)
	response, err := c.SecondaryConnection.AtConnection.ExecuteCommand(command, true)
	if err != nil {
		return nil, exceptions.NewAtSecondaryConnectException("Failed to execute " + command + " - " + err.Error())
	}

	return response, nil
}

// func (c *AtClient) Get(key common.AtKey, command string) (string, error) {}
// func (c *AtClient) GetLookupResponse(command string) (string, error) {}
// func (c *AtClient) getSelfKey(key common.SelfKey) (string, error) {}
// func (c *AtClient) getPublicKey(key common.PublicKey) (string, error) {}
// func (c *AtClient) getSharedKey(key common.SharedKey) (string, error) {}

// func (c *AtClient) getSharedByMeWithOther(key common.SelfKey) (string, error) {}
// func (c *AtClient) getSharedByOtherWithMe(key common.SelfKey) (string, error) {}

// func (c *AtClient) delete(key common.Atkey) (connections.Response, error) {}
