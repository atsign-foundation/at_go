package common

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Metadata struct {
	TTL             int        `json:"ttl"`
	TTB             int        `json:"ttb"`
	TTR             int        `json:"ttr"`
	CCD             bool       `json:"ccd"`
	CreatedBy       string     `json:"createdBy"`
	UpdatedBy       string     `json:"updatedBy"`
	AvailableAt     *time.Time `json:"availableAt,omitempty"`
	ExpiresAt       *time.Time `json:"expiresAt,omitempty"`
	RefreshAt       *time.Time `json:"refreshAt,omitempty"`
	CreatedAt       *time.Time `json:"createdAt,omitempty"`
	UpdatedAt       *time.Time `json:"updatedAt,omitempty"`
	Status          string     `json:"status,omitempty"`
	Version         int        `json:"version"`
	DataSignature   string     `json:"dataSignature,omitempty"`
	SharedKeyStatus string     `json:"sharedKeyStatus,omitempty"`
	IsPublic        bool       `json:"isPublic"`
	IsEncrypted     bool       `json:"isEncrypted"`
	IsHidden        bool       `json:"isHidden"`
	NamespaceAware  bool       `json:"namespaceAware"`
	IsBinary        bool       `json:"isBinary"`
	IsCached        bool       `json:"isCached"`
	SharedKeyEnc    string     `json:"sharedKeyEnc,omitempty"`
	PubKeyCS        string     `json:"pubKeyCS,omitempty"`
	Encoding        string     `json:"encoding,omitempty"`
	IVNonce         string     `json:"ivNonce,omitempty"`
}

func ParseDatetime(datetimeStr string) *time.Time {
	if datetimeStr != "" {
		t, err := time.Parse(time.RFC3339, datetimeStr)
		if err == nil {
			return &t
		}
	}
	return nil
}

func FromJSON(jsonStr string) (*Metadata, error) {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return nil, err
	}
	metadata := &Metadata{}

	fields := map[string]interface{}{
		"ttl":             &metadata.TTL,
		"ttb":             &metadata.TTB,
		"ttr":             &metadata.TTR,
		"ccd":             &metadata.CCD,
		"createdBy":       &metadata.CreatedBy,
		"updatedBy":       &metadata.UpdatedBy,
		"availableAt":     &metadata.AvailableAt,
		"expiresAt":       &metadata.ExpiresAt,
		"refreshAt":       &metadata.RefreshAt,
		"createdAt":       &metadata.CreatedAt,
		"updatedAt":       &metadata.UpdatedAt,
		"status":          &metadata.Status,
		"version":         &metadata.Version,
		"dataSignature":   &metadata.DataSignature,
		"sharedKeyStatus": &metadata.SharedKeyStatus,
		"isPublic":        &metadata.IsPublic,
		"isEncrypted":     &metadata.IsEncrypted,
		"isHidden":        &metadata.IsHidden,
		"namespaceAware":  &metadata.NamespaceAware,
		"isBinary":        &metadata.IsBinary,
		"isCached":        &metadata.IsCached,
		"sharedKeyEnc":    &metadata.SharedKeyEnc,
		"pubKeyCS":        &metadata.PubKeyCS,
		"encoding":        &metadata.Encoding,
		"ivNonce":         &metadata.IVNonce,
	}

	for field, target := range fields {
		value, exists := data[field]
		if exists {
			switch field {
			case "availableAt", "expiresAt", "refreshAt", "createdAt", "updatedAt":
				if valString, ok := value.(string); ok {
					valString = strings.Replace(valString, " ", "T", 1)
					if parsedTime := ParseDatetime(valString); parsedTime != nil {
						*target.(**time.Time) = parsedTime
					} else {
						return nil, errors.New("Error when trying to converse format of " + field)
					}
				}
			case "ttl", "ttb", "ttr":
				if valFloat, ok := value.(float64); ok {
					*target.(*int) = int(valFloat)
				} else {
					return nil, errors.New("Field '" + field + "' not valid")
				}
			case "ccd", "isPublic", "isEncrypted", "isHidden", "namespaceAware", "isBinary", "isCached":
				if valBool, ok := value.(bool); ok {
					*target.(*bool) = valBool
				} else {
					return nil, errors.New("Field '" + field + "' not valid")
				}
			case "version":
				if valFloat, ok := value.(float64); ok {
					*target.(*int) = int(valFloat)
				} else {
					return nil, errors.New("Field 'version' not valid")
				}
			case "createdBy", "updatedBy", "status", "dataSignature", "sharedKeyStatus", "sharedKeyEnc", "pubKeyCS", "encoding", "ivNonce":
				if valString, ok := value.(string); ok {
					*target.(*string) = valString
				} else {
					return nil, errors.New("Field '" + field + "' not valid")
				}
			}
		}
	}

	return metadata, nil
}

func (metadata *Metadata) String() string {
	s := ""
	if metadata.TTL > 0 {
		s += fmt.Sprintf(":ttl:%d", metadata.TTL)
	}
	if metadata.TTB > 0 {
		s += fmt.Sprintf(":ttb:%d", metadata.TTB)
	}
	if metadata.TTR > 0 {
		s += fmt.Sprintf(":ttr:%d", metadata.TTR)
	}
	if metadata.CCD {
		s += ":ccd:true"
	}
	if metadata.DataSignature != "" {
		s += fmt.Sprintf(":dataSignature:%s", metadata.DataSignature)
	}
	if metadata.SharedKeyStatus != "" {
		s += fmt.Sprintf(":sharedKeyStatus:%s", metadata.SharedKeyStatus)
	}
	if metadata.SharedKeyEnc != "" {
		s += fmt.Sprintf(":sharedKeyEnc:%s", metadata.SharedKeyEnc)
	}
	if metadata.PubKeyCS != "" {
		s += fmt.Sprintf(":pubKeyCS:%s", metadata.PubKeyCS)
	}
	if metadata.IsBinary {
		s += ":isBinary:true"
	} else {
		s += ":isBinary:false"
	}
	if metadata.IsEncrypted {
		s += ":isEncrypted:true"
	} else {
		s += ":isEncrypted:false"
	}
	if metadata.Encoding != "" {
		s += fmt.Sprintf(":encoding:%s", metadata.Encoding)
	}
	if metadata.IVNonce != "" {
		ivNonce, err := base64.StdEncoding.DecodeString(metadata.IVNonce)
		if err == nil {
			s += fmt.Sprintf(":ivNonce:%s", string(ivNonce))
		}
	}
	return s
}

func Squash(firstMetadata, secondMetadata *Metadata) *Metadata {
	metadata := &Metadata{}
	if firstMetadata.TTL != 0 {
		metadata.TTL = firstMetadata.TTL
	} else {
		metadata.TTL = secondMetadata.TTL
	}
	if firstMetadata.TTB != 0 {
		metadata.TTB = firstMetadata.TTB
	} else {
		metadata.TTB = secondMetadata.TTB
	}
	if firstMetadata.TTR != 0 {
		metadata.TTR = firstMetadata.TTR
	} else {
		metadata.TTR = secondMetadata.TTR
	}
	metadata.CCD = firstMetadata.CCD || secondMetadata.CCD
	if firstMetadata.AvailableAt != nil {
		metadata.AvailableAt = firstMetadata.AvailableAt
	} else {
		metadata.AvailableAt = secondMetadata.AvailableAt
	}
	if firstMetadata.ExpiresAt != nil {
		metadata.ExpiresAt = firstMetadata.ExpiresAt
	} else {
		metadata.ExpiresAt = secondMetadata.ExpiresAt
	}
	if firstMetadata.RefreshAt != nil {
		metadata.RefreshAt = firstMetadata.RefreshAt
	} else {
		metadata.RefreshAt = secondMetadata.RefreshAt
	}
	if firstMetadata.CreatedAt != nil {
		metadata.CreatedAt = firstMetadata.CreatedAt
	} else {
		metadata.CreatedAt = secondMetadata.CreatedAt
	}
	if firstMetadata.UpdatedAt != nil {
		metadata.UpdatedAt = firstMetadata.UpdatedAt
	} else {
		metadata.UpdatedAt = secondMetadata.UpdatedAt
	}
	if firstMetadata.DataSignature != "" {
		metadata.DataSignature = firstMetadata.DataSignature
	} else {
		metadata.DataSignature = secondMetadata.DataSignature
	}
	if firstMetadata.SharedKeyStatus != "" {
		metadata.SharedKeyStatus = firstMetadata.SharedKeyStatus
	} else {
		metadata.SharedKeyStatus = secondMetadata.SharedKeyStatus
	}
	if firstMetadata.SharedKeyEnc != "" {
		metadata.SharedKeyEnc = firstMetadata.SharedKeyEnc
	} else {
		metadata.SharedKeyEnc = secondMetadata.SharedKeyEnc
	}
	metadata.IsPublic = firstMetadata.IsPublic || secondMetadata.IsPublic
	metadata.IsEncrypted = firstMetadata.IsEncrypted || secondMetadata.IsEncrypted
	metadata.IsHidden = firstMetadata.IsHidden || secondMetadata.IsHidden
	metadata.NamespaceAware = firstMetadata.NamespaceAware || secondMetadata.NamespaceAware
	metadata.IsBinary = firstMetadata.IsBinary || secondMetadata.IsBinary
	metadata.IsCached = firstMetadata.IsCached || secondMetadata.IsCached
	if firstMetadata.PubKeyCS != "" {
		metadata.PubKeyCS = firstMetadata.PubKeyCS
	} else {
		metadata.PubKeyCS = secondMetadata.PubKeyCS
	}
	if firstMetadata.Encoding != "" {
		metadata.Encoding = firstMetadata.Encoding
	} else {
		metadata.Encoding = secondMetadata.Encoding
	}
	if firstMetadata.IVNonce != "" {
		metadata.IVNonce = firstMetadata.IVNonce
	} else {
		metadata.IVNonce = secondMetadata.IVNonce
	}
	return metadata
}
