package auth_util

import (
	"crypto/sha512"
	"strings"

	"github.com/atsign-foundation/at_go/at_client/common"
	"github.com/atsign-foundation/at_go/at_client/connections"
	"github.com/atsign-foundation/at_go/at_client/exceptions"
	"github.com/atsign-foundation/at_go/at_client/utils/encryption_util"
	"github.com/atsign-foundation/at_go/at_client/utils/key_utils"
	"github.com/atsign-foundation/at_go/at_client/utils/verb_builder"
)

const (
	HEX_ARRAY = "0123456789abcdef"
)

type AuthUtil struct{}

func NewAuthUtil() *AuthUtil {
	return &AuthUtil{}
}

func AuthenticateWithCram(conn connections.AtConnection, atSign common.AtSign, cramSecret string) *exceptions.AtException {
	fromCommand := verb_builder.NewFromVerbBuilder().SetSharedBy(atSign.AtSignStr).Build()
	fromResponse, err := conn.ExecuteCommand(fromCommand, true)
	if err != nil {
		return exceptions.NewAtException(err.Error())
	}
	if !strings.HasPrefix(fromResponse.GetRawDataResponse(), "data:") {
		return exceptions.NewAtUnauthenticatedException("Invalid response to 'from': " + fromResponse.GetRawDataResponse()).AtException
	}
	challenge := strings.Replace(fromResponse.GetRawDataResponse(), "data:", "", 1)
	cramDigest := getCramDigest(cramSecret, challenge)

	cramCommand := verb_builder.NewCRAMVerbBuilder().SetDigest(cramDigest).Build()
	cramResponse, err := conn.ExecuteCommand(cramCommand, true)
	if err != nil {
		return exceptions.NewAtException(err.Error())
	}
	if !strings.HasPrefix(cramResponse.GetRawDataResponse(), "data:success") {
		return exceptions.NewAtUnauthenticatedException("CRAM command failed: " + fromResponse.GetRawDataResponse()).AtException
	}
	return nil
}

func AuthenticateWithPkam(conn connections.AtConnection, atSign common.AtSign, keys map[string]string) error {
	fromCommand := verb_builder.NewFromVerbBuilder().SetSharedBy(atSign.AtSignStr).Build()
	fromResponse, err := conn.ExecuteCommand(fromCommand, true)
	if err != nil {
		return exceptions.NewAtException(err.Error())
	}

	challenge := strings.Replace(fromResponse.GetRawDataResponse(), "data:", "", 1)
	signature, err := encryption_util.NewEncryptionUtil().SignSHA256RSA(challenge, []byte(keys[key_utils.PkamPrivateKeyName]))
	if err != nil {
		return exceptions.NewAtException(err.Error())
	}

	pkamCommand := verb_builder.NewPKAMVerbBuilder().SetDigest(signature).Build()
	pkamResponse, err := conn.ExecuteCommand(pkamCommand, true)
	if err != nil {
		return exceptions.NewAtException(err.Error())
	}

	if !strings.HasPrefix(pkamResponse.GetRawDataResponse(), "data:success") {
		return exceptions.NewAtUnauthenticatedException("PKAM command failed: " + fromResponse.GetRawDataResponse()).AtException
	}
	return nil
}

func getCramDigest(cramSecret, challenge string) string {
	digestInput := cramSecret + challenge
	digestInputBytes := []byte(digestInput)

	hasher := sha512.New()
	hasher.Write(digestInputBytes)
	digest := hasher.Sum(nil)

	return bytesToHex(digest)
}

func bytesToHex(data []byte) string {
	hexChars := make([]byte, len(data)*2)
	for i, b := range data {
		hexChars[i*2] = HEX_ARRAY[b>>4]
		hexChars[i*2+1] = HEX_ARRAY[b&0x0F]
	}
	return string(hexChars)
}
