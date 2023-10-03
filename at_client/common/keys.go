package common

import (
	"errors"
	"fmt"
	"strings"

	"github.com/atsign-foundation/at_go/at_client/utils/key_utils"
)

type Keys struct{}

func NewKeys() *Keys {
	return &Keys{}
}

func KeysFromString(fullAtKeyName string) (AtKey, error) {
	keyStringUtil := key_utils.NewKeyStringUtil(fullAtKeyName)
	keyType := keyStringUtil.GetKeyType()
	keyName := keyStringUtil.GetKeyName()
	sharedBy := NewAtSign(keyStringUtil.GetSharedBy())
	sharedWithStr := keyStringUtil.GetSharedWith()
	var sharedWith *AtSign
	if sharedWithStr != "" {
		sharedWith = NewAtSign(sharedWithStr)
	}
	namespace := keyStringUtil.GetNamespace()
	isCached := keyStringUtil.IsCached()
	isHidden := keyStringUtil.IsHidden()

	var atKey AtKey

	switch keyType {
	case key_utils.KeyTypeInstance.PUBLIC_KEY:
		atKey = NewPublicKey(keyName, sharedBy)
	case key_utils.KeyTypeInstance.SHARED_KEY:
		if sharedWith.AtSignStr == "" {
			return nil, errors.New("SharedKey: shared_with may not be null")
		}
		atKey = NewSharedKey(keyName, sharedBy, sharedWith)
	case key_utils.KeyTypeInstance.SELF_KEY:
		atKey = NewSelfKey(keyName, sharedBy, sharedWith)
	case key_utils.KeyTypeInstance.PRIVATE_HIDDEN_KEY:
		atKey = NewPrivateHiddenKey(keyName, sharedBy)
	default:
		return nil, fmt.Errorf("Could not find KeyType for Key %s", fullAtKeyName)
	}

	atKey.SetNamespace(namespace)
	atKey.GetMetadata().IsCached = isCached
	if !atKey.GetMetadata().IsHidden {
		atKey.GetMetadata().IsHidden = isHidden
	}

	return atKey, nil
}

type AtKey interface {
	GetNamespace() string
	SetNamespace(namespace string) AtKey
	GetFullyQualifiedKeyName() string
	SetName(name string) AtKey
	GetName() string
	SetTimeToLive(ttl int) AtKey
	SetTimeToBirth(ttb int) AtKey
	String() string
	GetMetadata() *Metadata
	SetMetadata(m Metadata) AtKey
	GetSharedBy() *AtSign
	GetSharedWith() *AtSign
}

type AtKeyBase struct {
	Name       string
	SharedBy   *AtSign
	SharedWith *AtSign
	Namespace  string
	Metadata   Metadata
}

func (a *AtKeyBase) GetSharedBy() *AtSign {
	return a.SharedBy
}

func (a *AtKeyBase) GetSharedWith() *AtSign {
	return a.SharedWith
}

func (a *AtKeyBase) SetMetadata(m Metadata) AtKey {
	a.Metadata = m
	return a
}

func (a *AtKeyBase) GetNamespace() string {
	return a.Namespace
}

func (a *AtKeyBase) SetNamespace(namespace string) AtKey {
	if namespace != "" {
		namespace = strings.TrimLeft(namespace, ".")
		namespace = strings.TrimSpace(namespace)
	}
	a.Namespace = namespace
	return a
}

func (a *AtKeyBase) GetFullyQualifiedKeyName() string {
	if a.Namespace != "" {
		return a.Name + "." + a.Namespace
	}
	return a.Name
}

func (a *AtKeyBase) SetName(name string) AtKey {
	a.Name = strings.TrimSpace(name)
	return a
}

func (a *AtKeyBase) GetName() string {
	return a.Name
}

func (a *AtKeyBase) SetTimeToLive(ttl int) AtKey {
	a.Metadata.TTL = ttl
	return a
}

func (a *AtKeyBase) SetTimeToBirth(ttb int) AtKey {
	a.Metadata.TTB = ttb
	return a
}

func (a *AtKeyBase) String() string {
	s := ""
	if a.Metadata.IsPublic {
		s += "public:"
	} else if a.SharedBy != nil {
		s += a.SharedBy.AtSignStr + ":"
	}
	s += a.GetFullyQualifiedKeyName()
	if a.SharedBy != nil {
		s += a.SharedBy.AtSignStr
	}
	return s
}

func (a *AtKeyBase) GetMetadata() *Metadata {
	return &a.Metadata
}

type PublicKey struct {
	AtKeyBase
}

func NewPublicKey(name string, sharedBy *AtSign) *PublicKey {
	return &PublicKey{
		AtKeyBase: AtKeyBase{
			Name:     name,
			SharedBy: sharedBy,
		},
	}
}

func (pk *PublicKey) Cache(ttr int, ccd bool) *PublicKey {
	pk.Metadata.TTR = ttr
	pk.Metadata.CCD = ccd
	pk.Metadata.IsCached = (ttr != 0)
	return pk
}

type SelfKey struct {
	AtKeyBase
	SharedWith *AtSign
}

func NewSelfKey(name string, sharedBy *AtSign, sharedWith *AtSign) *SelfKey {
	return &SelfKey{
		AtKeyBase: AtKeyBase{
			Name:     name,
			SharedBy: sharedBy,
		},
		SharedWith: sharedWith,
	}
}

type SharedKey struct {
	AtKeyBase
	SharedWith *AtSign
}

func NewSharedKey(name string, sharedBy *AtSign, sharedWith *AtSign) *SharedKey {
	if sharedWith == nil {
		panic("SharedKey: sharedWith may not be nil")
	}
	return &SharedKey{
		AtKeyBase: AtKeyBase{
			Name:     name,
			SharedBy: sharedBy,
		},
		SharedWith: sharedWith,
	}
}

func (sk *SharedKey) Cache(ttr int, ccd bool) *SharedKey {
	sk.Metadata.TTR = ttr
	sk.Metadata.CCD = ccd
	sk.Metadata.IsCached = (ttr != 0)
	return sk
}

func SharedKeyFromString(key string) (*SharedKey, error) {
	if key == "" {
		return nil, errors.New("SharedKeyFromString: key may not be empty")
	}
	splitByColon := strings.Split(key, ":")
	if len(splitByColon) != 2 {
		return nil, errors.New("SharedKeyFromString: key must have structure @bob:foo.bar@alice")
	}
	sharedWithStr := splitByColon[0]
	splitByAtSign := strings.Split(splitByColon[1], "@")
	if len(splitByAtSign) != 2 {
		return nil, errors.New("SharedKeyFromString: key must have structure @bob:foo.bar@alice")
	}
	keyName := splitByAtSign[0]
	sharedBy := splitByAtSign[1]
	sharedKey := NewSharedKey(keyName, NewAtSign(sharedBy), NewAtSign(sharedWithStr))
	sharedKey.Name = keyName
	return sharedKey, nil
}

func (sk *SharedKey) GetSharedSharedKeyName() string {
	return sk.SharedWith.AtSignStr + ":shared_key" + sk.SharedBy.AtSignStr
}

type PrivateHiddenKey struct {
	AtKeyBase
}

func NewPrivateHiddenKey(name string, sharedBy *AtSign) *PrivateHiddenKey {
	return &PrivateHiddenKey{
		AtKeyBase: AtKeyBase{
			Name:     name,
			SharedBy: sharedBy,
		},
	}
}
