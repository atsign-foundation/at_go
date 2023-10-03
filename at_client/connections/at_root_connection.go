package connections

import (
	"context"
	"strings"
	"sync"

	"github.com/atsign-foundation/at_go/at_client/common"
	"github.com/atsign-foundation/at_go/at_client/exceptions"
)

var atRootConnection *AtRootConnection
var once sync.Once

type AtRootConnection struct {
	AtConnection *AtConnection
}

func GetAtRootConnectionInstance() *AtRootConnection {
	once.Do(func() {
		atRootConnection = &AtRootConnection{
			AtConnection: NewAtConnection("root.atsign.org", 64, context.Background(), false),
		}
	})
	return atRootConnection
}

func (arc *AtRootConnection) ParseRawResponse(rawResponse string) *Response {
	if strings.HasSuffix(rawResponse, "@") {
		rawResponse = rawResponse[:len(rawResponse)-1]
	}
	return NewResponse().SetRawDataResponse(strings.TrimSpace(rawResponse))
}

func (arc *AtRootConnection) FindSecondary(atSign common.AtSign) (*Address, *exceptions.AtException) {
	if !arc.AtConnection.connected {
		err := arc.AtConnection.Connect()
		if err != nil {
			return nil, exceptions.NewAtException("Root Connection failed - " + err.Error())
		}
	}
	response, err := arc.AtConnection.ExecuteCommand(atSign.WithoutPrefix, true)
	if err != nil || response.rawDataResponse == "" {
		return nil, exceptions.NewAtException("Root lookup returned null for " + atSign.AtSignStr)
	}
	address, err := AddressFromString(response.rawDataResponse)
	if address != nil {
		return NewAddress(address.host, address.port), nil
	} else if err != nil {
		return nil, exceptions.NewAtException("Root lookup returned error for " + atSign.AtSignStr + ": " + err.Error())
	}
	return nil, nil
}
