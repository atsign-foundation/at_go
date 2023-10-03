package connections

import (
	"fmt"
	"strconv"
	"strings"
)

type Address struct {
	host string
	port int
}

func NewAddress(host string, port int) *Address {
	return &Address{host, port}
}

func (a *Address) Host() string {
	return a.host
}

func (a *Address) Port() int {
	return a.port
}

func (a *Address) String() string {
	return a.host + ":" + strconv.Itoa(a.port)
}

func AddressFromString(hostAndPort string) (*Address, error) {
	parts := strings.Split(hostAndPort, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("Cannot construct Address from malformed host:port string '%s'", hostAndPort)
	}
	host := parts[0]
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("Cannot construct Address from malformed host:port string '%s'", hostAndPort)
	}
	return NewAddress(host, port), nil
}
