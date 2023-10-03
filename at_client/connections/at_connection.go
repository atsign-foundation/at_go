package connections

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
)

type AtConnection struct {
	host       string
	port       int
	ctx        context.Context
	config     *tls.Config
	verbose    bool
	connection *tls.Conn
	connected  bool
}

func NewAtConnection(host string, port int, ctx context.Context, verbose bool) *AtConnection {

	// config := &tls.Config{
	// 	MinVersion: tls.VersionTLS12,
	// 	MaxVersion: tls.VersionTLS13,
	// }

	return &AtConnection{
		host: host,
		port: port,
		ctx:  ctx,
		// config:    config,
		verbose:   verbose,
		connected: false,
	}
}

func (atconn *AtConnection) String() string {
	return fmt.Sprintf("%s:%d", atconn.host, atconn.port)
}

func (atconn *AtConnection) write(data string) {
	atconn.connection.Write([]byte(data))
}

func (atconn *AtConnection) read() string {
	response := ""
	buf := make([]byte, 1024)
	for {
		chunk, err := atconn.connection.Read(buf)
		if err != nil {
			break
		}
		// fmt.Println(string(buf))
		response += string(buf[:chunk])
		if string(buf[:chunk]) == "@" || strings.Contains(string(buf[:chunk]), "\n") {
			break
		}
	}
	return response
}

func (atconn *AtConnection) IsConnected() bool {
	return atconn.connected
}

func (atconn *AtConnection) Connect() error {
	if !atconn.connected {
		address := fmt.Sprintf("%s:%d", atconn.host, atconn.port)
		dirconn, err := tls.Dial("tcp", address, atconn.config)
		if err != nil {
			return err
		}
		atconn.connection = dirconn
		atconn.connected = true
		atconn.read()
	}
	return nil
}

func (atconn *AtConnection) Disconnect() {
	atconn.connection.Close()
	atconn.connected = false
}

func (atconn *AtConnection) ExecuteCommand(command string, readTheResponse bool) (*Response, error) {
	// atconn.connection.SetWriteDeadline(time.Now().Add(10*time.Second))
	response := NewResponse()
	if !atconn.connected {
		return response, fmt.Errorf("Not connected")
	}

	if !strings.HasSuffix(command, "\n") {
		command += "\n"
	}
	atconn.write(command)

	if atconn.verbose {
		fmt.Printf("\tSENT: %s\n", command)
	}

	if readTheResponse {
		rawResponse := atconn.read()
		if atconn.verbose {
			fmt.Printf("\tRCVD: %s\n", rawResponse)
		}
		response := atRootConnection.ParseRawResponse(rawResponse)
		return response, nil
	}

	// TODO: manage exceptions/retry

	return response, nil
}
