package key_utils

import (
	"strings"
)

type KeyType struct {
	PUBLIC_KEY         string
	SHARED_KEY         string
	SELF_KEY           string
	PRIVATE_HIDDEN_KEY string
}

var KeyTypeInstance = KeyType{
	PUBLIC_KEY:         "PUBLIC_KEY",
	SHARED_KEY:         "SHARED_KEY",
	SELF_KEY:           "SELF_KEY",
	PRIVATE_HIDDEN_KEY: "PRIVATE_HIDDEN_KEY",
}

type KeyStringUtil struct {
	fullKeyName string
	keyName     string
	keyType     string
	namespace   string
	sharedBy    string
	sharedWith  string
	isCached    bool
	isHidden    bool
}

func NewKeyStringUtil(fullKeyName string) *KeyStringUtil {
	keyUtil := &KeyStringUtil{
		fullKeyName: fullKeyName,
		isCached:    false,
		isHidden:    false,
	}
	keyUtil.evaluate(fullKeyName)
	return keyUtil
}

func (ks *KeyStringUtil) GetFullKeyName() string {
	return ks.fullKeyName
}

func (ks *KeyStringUtil) GetKeyName() string {
	return ks.keyName
}

func (ks *KeyStringUtil) GetNamespace() string {
	return ks.namespace
}

func (ks *KeyStringUtil) GetKeyType() string {
	return ks.keyType
}

func (ks *KeyStringUtil) GetSharedBy() string {
	return ks.sharedBy
}

func (ks *KeyStringUtil) GetSharedWith() string {
	return ks.sharedWith
}

func (ks *KeyStringUtil) IsCached() bool {
	return ks.isCached
}

func (ks *KeyStringUtil) IsHidden() bool {
	return ks.isHidden
}

func (ks *KeyStringUtil) evaluate(fullKeyName string) {
	split1 := strings.Split(fullKeyName, ":")

	if len(split1) > 1 {
		if split1[0] == "public" || (split1[0] == "cached" && split1[1] == "public") {
			ks.keyType = KeyTypeInstance.PUBLIC_KEY
		} else if split1[0] == "private" || split1[0] == "privatekey" {
			ks.keyType = KeyTypeInstance.PRIVATE_HIDDEN_KEY
			ks.isHidden = true
		}

		if strings.HasPrefix(split1[0], "@") || strings.HasPrefix(split1[1], "@") {
			if ks.keyType == "" {
				ks.keyType = KeyTypeInstance.SHARED_KEY
			}
			if strings.HasPrefix(split1[0], "@") {
				ks.sharedWith = split1[0][1:]
			} else {
				ks.sharedWith = split1[1][1:]
			}
		}

		split2 := strings.Split(split1[len(split1)-1], "@")
		ks.keyName = split2[0]
		ks.sharedBy = split2[1]

		if split1[0] == "cached" {
			ks.isCached = true
		}

		if ks.sharedBy == ks.sharedWith {
			ks.keyType = KeyTypeInstance.SELF_KEY
		}
	} else {
		if strings.HasPrefix(split1[0], "_") {
			ks.keyType = KeyTypeInstance.PRIVATE_HIDDEN_KEY
		} else {
			ks.keyType = KeyTypeInstance.SELF_KEY
		}

		split2 := strings.Split(split1[0], "@")
		ks.keyName = split2[0]
		ks.sharedBy = split2[1]

		if strings.HasPrefix(ks.keyName, "shared_key") {
			ks.namespace = ""
		}
	}

	if ks.sharedBy != "" {
		ks.sharedBy = "@" + ks.sharedBy
	}
	if ks.sharedWith != "" {
		ks.sharedWith = "@" + ks.sharedWith
	}
	if !ks.isHidden {
		ks.isHidden = strings.HasPrefix(ks.keyName, "_")
	}
}
