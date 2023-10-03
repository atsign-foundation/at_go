package connections

import (
	"context"
	"errors"
	"strings"
)

type AtSecondaryConnection struct {
	AtConnection *AtConnection
}

func NewAtSecondaryConnection(address Address, verbose bool) *AtSecondaryConnection {
	var atSecondaryConnection = &AtSecondaryConnection{
		AtConnection: NewAtConnection(address.host, address.port, context.Background(), verbose),
	}
	atSecondaryConnection.AtConnection.Connect()
	return atSecondaryConnection
}

func ParseRawResponse(rawResponse string) (*Response, error) {
	if strings.HasSuffix(rawResponse, "@") {
		rawResponse = rawResponse[:len(rawResponse)-1]
	}
	rawResponse = strings.TrimSpace(rawResponse)

	dataIndex := strings.Index(rawResponse, "data:")
	errorIndex := strings.Index(rawResponse, "error:")
	notificationIndex := strings.Index(rawResponse, "notification")

	response := NewResponse()

	if dataIndex > -1 {
		data := strings.Split(rawResponse[dataIndex+len("data:"):], "\n")[0]
		response.SetRawDataResponse(data)
	} else if errorIndex > -1 {
		errorMsg := rawResponse[errorIndex+len("error:"):]
		response.SetRawErrorResponse(errorMsg)
	} else if notificationIndex > -1 {
		notification := rawResponse[notificationIndex+len("notification:"):]
		response.SetRawDataResponse(notification)
	} else {
		return nil, errors.New("Invalid response from server: " + rawResponse)
	}
	return response, nil
}
