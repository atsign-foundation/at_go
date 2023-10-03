package key_utils

import (
	"crypto/aes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/atsign-foundation/at_go/at_client/utils/encryption_util"
)

type KeysUtil struct{}

var (
	// os.Getenv("HOME")
	userHomeDir, err          = os.UserHomeDir()
	expectedKeysFilesLocation = filepath.Join(userHomeDir, ".atsign", "keys")
	legacyKeysFilesLocation   = func() string {
		wd, err := os.Getwd()
		if err != nil {
			return ""
		} else {
			return filepath.Join(wd, "\\..\\..\\keys")
		}
	}()
	keysFileSuffix = "_key.atKeys"
)

const (
	PkamPublicKeyName        = "aesPkamPublicKey"
	PkamPrivateKeyName       = "aesPkamPrivateKey"
	EncryptionPublicKeyName  = "aesEncryptPublicKey"
	EncryptionPrivateKeyName = "aesEncryptPrivateKey"
	SelfEncryptionKeyName    = "selfEncryptionKey"
)

func NewKeysUtil() *KeysUtil {
	return &KeysUtil{}
}

func (ku *KeysUtil) saveKeys(atSign string, keys map[string]string) error {
	expectedKeysDirectory := filepath.Dir(expectedKeysFilesLocation)
	if err := os.MkdirAll(expectedKeysDirectory, os.ModePerm); err != nil {
		return err
	}

	encryptionUtil := encryption_util.NewEncryptionUtil()
	iv := make([]byte, aes.BlockSize) // zero iv

	filePath := ku.getKeysFile(atSign, expectedKeysFilesLocation)
	selfEncryptionKey := keys[SelfEncryptionKeyName]

	encryptedKeys := make(map[string]string)

	keysToEncrypt := []string{
		PkamPublicKeyName,
		PkamPrivateKeyName,
		EncryptionPublicKeyName,
		EncryptionPrivateKeyName,
	}

	for _, keyName := range keysToEncrypt {
		if encryptedKey, err := encryptionUtil.AesEncryptFromBase64(keys[keyName], selfEncryptionKey, iv); err == nil {
			encryptedKeys[keyName] = encryptedKey
		} else {
			return err
		}
	}

	encryptedKeys[SelfEncryptionKeyName] = selfEncryptionKey

	jsonData, err := json.MarshalIndent(encryptedKeys, "", "    ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(filePath, jsonData, os.ModePerm); err != nil {
		return err
	}

	return nil
}

func (ku *KeysUtil) LoadKeys(atSign string) (map[string]string, error) {
	encryptionUtil := encryption_util.NewEncryptionUtil()
	iv := make([]byte, aes.BlockSize) // zero iv

	file := ku.getKeysFile(atSign, expectedKeysFilesLocation)
	if _, err := os.Stat(file); os.IsNotExist(err) {
		file := ku.getKeysFile(atSign, legacyKeysFilesLocation)
		if _, err := os.Stat(file); os.IsNotExist(err) {
			return nil, fmt.Errorf("loadKeys: No file called %s%s at %s or %s\n"+
				"\tKeys files are expected to be in ~/.atsign/keys/ (canonical location) or ./keys/ (legacy location)",
				atSign, keysFileSuffix, expectedKeysFilesLocation, legacyKeysFilesLocation)
		}
	}

	jsonData, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var encryptedKeys map[string]string
	if err := json.Unmarshal(jsonData, &encryptedKeys); err != nil {
		return nil, err
	}

	selfEncryptionKey := encryptedKeys[SelfEncryptionKeyName]
	keys := make(map[string]string)

	keysToDecrypt := []string{
		PkamPublicKeyName,
		PkamPrivateKeyName,
		EncryptionPublicKeyName,
		EncryptionPrivateKeyName,
	}

	for _, keyName := range keysToDecrypt {
		if decryptedKey, err := encryptionUtil.AesDecryptFromBase64(encryptedKeys[keyName], selfEncryptionKey, iv); err == nil {
			keys[keyName] = decryptedKey
		} else {
			return nil, err
		}
	}

	return keys, nil
}

func (ku *KeysUtil) getKeysFile(atSign string, folderToLookIn string) string {
	return filepath.Join(folderToLookIn, atSign+keysFileSuffix)
}
