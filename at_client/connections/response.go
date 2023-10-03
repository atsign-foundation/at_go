package connections

import (
	"strings"

	"github.com/atsign-foundation/at_go/at_client/exceptions"
)

type Response struct {
	rawDataResponse  string
	rawErrorResponse string
	errorCode        string
	errorText        string
}

func (r *Response) GetRawDataResponse() string {
	return r.rawDataResponse
}

func (r *Response) SetRawDataResponse(s string) *Response {
	r.rawDataResponse = s
	r.rawErrorResponse = ""
	r.errorCode = ""
	r.errorText = ""
	return r
}

func (r *Response) GetRawErrorResponse() string {
	return r.rawErrorResponse
}

func (r *Response) SetRawErrorResponse(s string) *Response {
	r.rawErrorResponse = s
	r.rawDataResponse = ""

	errorCodeSegment := strings.TrimSpace(s[:strings.Index(s, ":")])
	separatedByHyphen := strings.Split(errorCodeSegment, "-")
	r.errorCode = strings.TrimSpace(separatedByHyphen[0])

	r.errorText = strings.TrimSpace(strings.Replace(s, errorCodeSegment+":", "", 1))
	return r
}

func (r *Response) IsError() bool {
	return r.rawErrorResponse != ""
}

func (r *Response) GetErrorCode() string {
	return r.errorCode
}

func (r *Response) GetErrorText() string {
	return r.errorText
}

func (r *Response) GetException() error {
	if !r.IsError() {
		return nil
	}

	switch r.errorCode {
	case "AT0001":
		return exceptions.NewAtServerRuntimeException(r.errorText)
	case "AT0003":
		return exceptions.NewAtInvalidSyntaxException(r.errorText)
	case "AT0005":
		return exceptions.NewAtBufferOverFlowException(r.errorText)
	case "AT0006":
		return exceptions.NewAtOutboundConnectionLimitException(r.errorText)
	case "AT0007":
		return exceptions.NewAtSecondaryNotFoundException(r.errorText)
	case "AT0008":
		return exceptions.NewAtHandShakeException(r.errorText)
	case "AT0009":
		return exceptions.NewAtUnauthorizedException(r.errorText)
	case "AT0010":
		return exceptions.NewAtInternalServerError(r.errorText)
	case "AT0011":
		return exceptions.NewAtInternalServerException(r.errorText)
	case "AT0012":
		return exceptions.NewAtInboundConnectionLimitException(r.errorText)
	case "AT0013":
		return exceptions.NewAtBlockedConnectionException(r.errorText)
	case "AT0015":
		return exceptions.NewAtKeyNotFoundException(r.errorText)
	case "AT0016":
		return exceptions.NewAtInvalidAtKeyException(r.errorText)
	case "AT0021":
		return exceptions.NewAtSecondaryConnectException(r.errorText)
	case "AT0022":
		return exceptions.NewAtIllegalArgumentException(r.errorText)
	case "AT0023":
		return exceptions.NewAtTimeoutException(r.errorText)
	case "AT0024":
		return exceptions.NewAtServerIsPausedException(r.errorText)
	case "AT0401":
		return exceptions.NewAtUnauthenticatedException(r.errorText)
	default:
		return exceptions.NewAtNewErrorCodeException(r.errorCode + ": " + r.errorText)
	}
}

func NewResponse() *Response {
	return &Response{}
}
