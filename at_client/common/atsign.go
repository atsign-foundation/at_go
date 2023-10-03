package common

import (
	"strings"
)

type AtSign struct {
	AtSignStr     string
	WithoutPrefix string
}

func NewAtSign(atSign string) *AtSign {
	return &AtSign{
		AtSignStr:     formatAtSign(atSign),
		WithoutPrefix: strings.TrimLeft(formatAtSign(atSign), "@"),
	}
}

func formatAtSign(atSignStr string) string {
	atSignStr = strings.TrimSpace(atSignStr)
	if !strings.HasPrefix(atSignStr, "@") {
		atSignStr = "@" + atSignStr
	}
	return atSignStr
}

func (aS *AtSign) equals(other AtSign) bool {
	return aS.AtSignStr == other.AtSignStr
}
