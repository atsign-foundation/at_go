package verb_builder

import (
	"fmt"

	"github.com/atsign-foundation/at_go/at_client/common"
)

type VerbBuilder interface {
	build() string
}

type FromVerbBuilder struct {
	sharedBy string
}

func NewFromVerbBuilder() *FromVerbBuilder {
	return &FromVerbBuilder{}
}

func (builder *FromVerbBuilder) SetSharedBy(sharedBy string) *FromVerbBuilder {
	builder.sharedBy = sharedBy
	return builder
}

func (builder *FromVerbBuilder) Build() string {
	return fmt.Sprintf("from:%s", builder.sharedBy)
}

type PKAMVerbBuilder struct {
	digest string
}

func NewPKAMVerbBuilder() *PKAMVerbBuilder {
	return &PKAMVerbBuilder{}
}

func (builder *PKAMVerbBuilder) SetDigest(digest string) *PKAMVerbBuilder {
	builder.digest = digest
	return builder
}

func (builder *PKAMVerbBuilder) Build() string {
	return fmt.Sprintf("pkam:%s", builder.digest)
}

type CRAMVerbBuilder struct {
	digest string
}

func NewCRAMVerbBuilder() *CRAMVerbBuilder {
	return &CRAMVerbBuilder{}
}

func (builder *CRAMVerbBuilder) SetDigest(digest string) *CRAMVerbBuilder {
	builder.digest = digest
	return builder
}

func (builder *CRAMVerbBuilder) Build() string {
	return fmt.Sprintf("cram:%s", builder.digest)
}

type ScanVerbBuilder struct {
	regex      string
	fromAtSign string
	showHidden bool
}

func NewScanVerbBuilder() *ScanVerbBuilder {
	return &ScanVerbBuilder{}
}

func (builder *ScanVerbBuilder) SetRegex(regex string) *ScanVerbBuilder {
	builder.regex = regex
	return builder
}

func (builder *ScanVerbBuilder) SetFromAtSign(fromAtSign string) *ScanVerbBuilder {
	builder.fromAtSign = fromAtSign
	return builder
}

func (builder *ScanVerbBuilder) SetShowHidden(showHidden bool) *ScanVerbBuilder {
	builder.showHidden = showHidden
	return builder
}

func (builder *ScanVerbBuilder) Build() string {
	command := "scan"

	if builder.showHidden {
		command += ":showHidden:true"
	}

	if builder.fromAtSign != "" {
		command += ":" + builder.fromAtSign
	}

	if builder.regex != "" {
		command += " " + builder.regex
	}

	return command
}

type UpdateVerbBuilder struct {
	key           string
	sharedBy      string
	sharedWith    string
	isHidden      bool
	isPublic      bool
	isCached      bool
	ttl           int
	ttb           int
	ttr           int
	ccd           bool
	isBinary      bool
	isEncrypted   bool
	dataSignature string
	sharedKeyEnc  string
	pubKeyCS      string
	encoding      string
	value         string
}

func NewUpdateVerbBuilder() *UpdateVerbBuilder {
	return &UpdateVerbBuilder{}
}

func (builder *UpdateVerbBuilder) SetKeyName(key string) *UpdateVerbBuilder {
	builder.key = key
	return builder
}

func (builder *UpdateVerbBuilder) SetSharedBy(sharedBy string) *UpdateVerbBuilder {
	builder.sharedBy = sharedBy
	return builder
}

func (builder *UpdateVerbBuilder) SetSharedWith(sharedWith string) *UpdateVerbBuilder {
	builder.sharedWith = sharedWith
	return builder
}

func (builder *UpdateVerbBuilder) SetIsHidden(isHidden bool) *UpdateVerbBuilder {
	builder.isHidden = isHidden
	return builder
}

func (builder *UpdateVerbBuilder) SetIsPublic(isPublic bool) *UpdateVerbBuilder {
	builder.isPublic = isPublic
	return builder
}

func (builder *UpdateVerbBuilder) SetIsCached(isCached bool) *UpdateVerbBuilder {
	builder.isCached = isCached
	return builder
}

func (builder *UpdateVerbBuilder) SetTTL(ttl int) *UpdateVerbBuilder {
	builder.ttl = ttl
	return builder
}

func (builder *UpdateVerbBuilder) SetTTB(ttb int) *UpdateVerbBuilder {
	builder.ttb = ttb
	return builder
}

func (builder *UpdateVerbBuilder) SetTTR(ttr int) *UpdateVerbBuilder {
	builder.ttr = ttr
	return builder
}

func (builder *UpdateVerbBuilder) SetCCD(ccd bool) *UpdateVerbBuilder {
	builder.ccd = ccd
	return builder
}

func (builder *UpdateVerbBuilder) SetIsBinary(isBinary bool) *UpdateVerbBuilder {
	builder.isBinary = isBinary
	return builder
}

func (builder *UpdateVerbBuilder) SetIsEncrypted(isEncrypted bool) *UpdateVerbBuilder {
	builder.isEncrypted = isEncrypted
	return builder
}

func (builder *UpdateVerbBuilder) SetDataSignature(dataSignature string) *UpdateVerbBuilder {
	builder.dataSignature = dataSignature
	return builder
}

func (builder *UpdateVerbBuilder) SetSharedKeyEnc(sharedKeyEnc string) *UpdateVerbBuilder {
	builder.sharedKeyEnc = sharedKeyEnc
	return builder
}

func (builder *UpdateVerbBuilder) SetPubKeyCS(pubKeyCS string) *UpdateVerbBuilder {
	builder.pubKeyCS = pubKeyCS
	return builder
}

func (builder *UpdateVerbBuilder) SetEncoding(encoding string) *UpdateVerbBuilder {
	builder.encoding = encoding
	return builder
}

func (builder *UpdateVerbBuilder) SetValue(value string) *UpdateVerbBuilder {
	builder.value = value
	return builder
}

func (builder *UpdateVerbBuilder) SetMetadata(metadata *common.Metadata) *UpdateVerbBuilder {
	builder.SetIsHidden(metadata.IsHidden)
	builder.SetIsPublic(metadata.IsPublic)
	builder.SetIsCached(metadata.IsCached)
	builder.SetTTL(metadata.TTL)
	builder.SetTTB(metadata.TTB)
	builder.SetTTR(metadata.TTR)
	builder.SetCCD(metadata.CCD)
	builder.SetIsBinary(metadata.IsBinary)
	builder.SetIsEncrypted(metadata.IsEncrypted)
	builder.SetDataSignature(metadata.DataSignature)
	builder.SetSharedKeyEnc(metadata.SharedKeyEnc)
	builder.SetPubKeyCS(metadata.PubKeyCS)
	builder.SetEncoding(metadata.Encoding)
	return builder
}

func (builder *UpdateVerbBuilder) WithAtKey(key common.AtKey, value string) *UpdateVerbBuilder {
	builder.SetKeyName(key.GetName())
	builder.SetSharedBy(key.GetSharedBy().AtSignStr)
	if key.GetSharedWith().AtSignStr != "" {
		builder.SetSharedWith(key.GetSharedWith().AtSignStr)
	}
	builder.SetIsCached(key.GetMetadata().IsCached)
	builder.SetIsHidden(key.GetMetadata().IsHidden)
	builder.SetIsPublic(key.GetMetadata().IsPublic)
	builder.SetMetadata(key.GetMetadata())
	builder.SetValue(value)
	return builder
}

func (builder *UpdateVerbBuilder) Build() string {
	command := "update"
	command += fmt.Sprintf(":%s", builder.key)

	if builder.sharedBy != "" {
		command += fmt.Sprintf(":sharedBy:%s", builder.sharedBy)
	}

	if builder.sharedWith != "" {
		command += fmt.Sprintf(":sharedWith:%s", builder.sharedWith)
	}

	if builder.isHidden {
		command += ":isHidden:true"
	}

	if builder.isPublic {
		command += ":isPublic:true"
	}

	if builder.isCached {
		command += ":isCached:true"
	}

	if builder.ttl > 0 {
		command += fmt.Sprintf(":ttl:%d", builder.ttl)
	}

	if builder.ttb > 0 {
		command += fmt.Sprintf(":ttb:%d", builder.ttb)
	}

	if builder.ttr > 0 {
		command += fmt.Sprintf(":ttr:%d", builder.ttr)
	}

	if builder.ccd {
		command += ":ccd:true"
	}

	if builder.isBinary {
		command += ":isBinary:true"
	} else {
		command += ":isBinary:false"
	}

	if builder.isEncrypted {
		command += ":isEncrypted:true"
	} else {
		command += ":isEncrypted:false"
	}

	if builder.dataSignature != "" {
		command += fmt.Sprintf(":dataSignature:%s", builder.dataSignature)
	}

	if builder.sharedKeyEnc != "" {
		command += fmt.Sprintf(":sharedKeyEnc:%s", builder.sharedKeyEnc)
	}

	if builder.pubKeyCS != "" {
		command += fmt.Sprintf(":pubKeyCS:%s", builder.pubKeyCS)
	}

	if builder.encoding != "" {
		command += fmt.Sprintf(":encoding:%s", builder.encoding)
	}

	command += fmt.Sprintf(":%s", builder.value)

	return command
}
