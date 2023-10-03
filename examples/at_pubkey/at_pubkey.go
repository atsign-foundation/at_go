package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
)

func main() {
	args := os.Args
	port := flag.String("port", "64", "port to connect")
	atsign := flag.String("atsign", args[1], "atSign to query")
	flag.Parse()

	config := &tls.Config{}

	dirconn, err := tls.Dial("tcp", "root.atsign.org:"+*port, config)
	if err != nil {
		log.Fatal(err)
	}

	buf1 := make([]byte, 256)
	n1, err := dirconn.Read(buf1)
	if err != nil && err != io.EOF {
		log.Fatal(err)
	}
	if string(buf1[:n1]) != "@" {
		log.Fatal("No prompt from atDirectory")
	}

	_, err = io.WriteString(dirconn, *atsign+"\n")
	if err != nil {
		log.Fatal("client write error:", err)
	}
	if err = dirconn.CloseWrite(); err != nil {
		log.Fatal(err)
	}

	buf2 := make([]byte, 256)
	n2, err := dirconn.Read(buf2)
	if err != nil && err != io.EOF {
		log.Fatal(err)
	}

	atSignURL := string(buf2[:n2-3])

	fmt.Println("atServer URL:", atSignURL)
	dirconn.Close()

	secconn, err := tls.Dial("tcp", atSignURL, config)
	if err != nil {
		log.Fatal(err)
	}

	buf3 := make([]byte, 256)
	n3, err := secconn.Read(buf3)
	if err != nil && err != io.EOF {
		log.Fatal(err)
	}
	if string(buf3[:n3]) != "@" {
		log.Fatal("No prompt from atServer")
	}

	_, err = io.WriteString(secconn, "lookup:publickey@"+*atsign+"\n")
	if err != nil {
		log.Fatal("client write error:", err)
	}
	if err = secconn.CloseWrite(); err != nil {
		log.Fatal(err)
	}

	buf4 := make([]byte, 512)
	n4, err := secconn.Read(buf4)
	if err != nil && err != io.EOF {
		log.Fatal(err)
	}

	atSignPublicKey := string(buf4[5 : n4-2])

	fmt.Println("atServer public key:", atSignPublicKey)
	secconn.Close()
}
