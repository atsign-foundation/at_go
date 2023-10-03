package exceptions

type AtException struct {
	message string
}

func NewAtException(message string) *AtException {
	return &AtException{message}
}

func (e *AtException) Error() string {
	return e.message
}

type AtServerRuntimeException struct {
	*AtException
}

func NewAtServerRuntimeException(message string) *AtServerRuntimeException {
	return &AtServerRuntimeException{NewAtException(message)}
}

type AtInvalidSyntaxException struct {
	*AtException
}

func NewAtInvalidSyntaxException(message string) *AtInvalidSyntaxException {
	return &AtInvalidSyntaxException{NewAtException(message)}
}

type AtBufferOverFlowException struct {
	*AtException
}

func NewAtBufferOverFlowException(message string) *AtBufferOverFlowException {
	return &AtBufferOverFlowException{NewAtException(message)}
}

type AtOutboundConnectionLimitException struct {
	*AtException
}

func NewAtOutboundConnectionLimitException(message string) *AtOutboundConnectionLimitException {
	return &AtOutboundConnectionLimitException{NewAtException(message)}
}

type AtSecondaryNotFoundException struct {
	*AtException
}

func NewAtSecondaryNotFoundException(message string) *AtSecondaryNotFoundException {
	return &AtSecondaryNotFoundException{NewAtException(message)}
}

type AtHandShakeException struct {
	*AtException
}

func NewAtHandShakeException(message string) *AtHandShakeException {
	return &AtHandShakeException{NewAtException(message)}
}

type AtUnauthorizedException struct {
	*AtException
}

func NewAtUnauthorizedException(message string) *AtUnauthorizedException {
	return &AtUnauthorizedException{NewAtException(message)}
}

type AtInternalServerError struct {
	*AtException
}

func NewAtInternalServerError(message string) *AtInternalServerError {
	return &AtInternalServerError{NewAtException(message)}
}

type AtInternalServerException struct {
	*AtException
}

func NewAtInternalServerException(message string) *AtInternalServerException {
	return &AtInternalServerException{NewAtException(message)}
}

type AtInboundConnectionLimitException struct {
	*AtException
}

func NewAtInboundConnectionLimitException(message string) *AtInboundConnectionLimitException {
	return &AtInboundConnectionLimitException{NewAtException(message)}
}

type AtBlockedConnectionException struct {
	*AtException
}

func NewAtBlockedConnectionException(message string) *AtBlockedConnectionException {
	return &AtBlockedConnectionException{NewAtException(message)}
}

type AtKeyNotFoundException struct {
	*AtException
}

func NewAtKeyNotFoundException(message string) *AtKeyNotFoundException {
	return &AtKeyNotFoundException{NewAtException(message)}
}

type AtInvalidAtKeyException struct {
	*AtException
}

func NewAtInvalidAtKeyException(message string) *AtInvalidAtKeyException {
	return &AtInvalidAtKeyException{NewAtException(message)}
}

type AtSecondaryConnectException struct {
	*AtException
}

func NewAtSecondaryConnectException(message string) *AtSecondaryConnectException {
	return &AtSecondaryConnectException{NewAtException(message)}
}

type AtIllegalArgumentException struct {
	*AtException
}

func NewAtIllegalArgumentException(message string) *AtIllegalArgumentException {
	return &AtIllegalArgumentException{NewAtException(message)}
}

type AtTimeoutException struct {
	*AtException
}

func NewAtTimeoutException(message string) *AtTimeoutException {
	return &AtTimeoutException{NewAtException(message)}
}

type AtServerIsPausedException struct {
	*AtException
}

func NewAtServerIsPausedException(message string) *AtServerIsPausedException {
	return &AtServerIsPausedException{NewAtException(message)}
}

type AtUnauthenticatedException struct {
	*AtException
}

func NewAtUnauthenticatedException(message string) *AtUnauthenticatedException {
	return &AtUnauthenticatedException{NewAtException(message)}
}

type AtNewErrorCodeException struct {
	*AtException
}

func NewAtNewErrorCodeException(message string) *AtNewErrorCodeException {
	return &AtNewErrorCodeException{NewAtException(message)}
}

type AtResponseHandlingException struct {
	*AtException
}

func NewAtResponseHandlingException(message string) *AtResponseHandlingException {
	return &AtResponseHandlingException{NewAtException(message)}
}

type AtEncryptionException struct {
	*AtException
}

func NewAtEncryptionException(message string) *AtEncryptionException {
	return &AtEncryptionException{NewAtException(message)}
}

type AtDecryptionException struct {
	*AtException
}

func NewAtDecryptionException(message string) *AtDecryptionException {
	return &AtDecryptionException{NewAtException(message)}
}

type AtRegistrarException struct {
	*AtException
}

func NewAtRegistrarException(message string) *AtRegistrarException {
	return &AtRegistrarException{NewAtException(message)}
}
