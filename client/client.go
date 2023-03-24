package main

import (
	"net"
	"os"
)

const (
	HOST = "localhost"
	PORT = "8080"
	TYPE = "tcp"
)

func main() {
	tcpServer, err := net.ResolveTCPAddr(TYPE, HOST+":"+PORT)

	if err != nil {
		println("ResolveTCPAddr failed:", err.Error())
		os.Exit(1)
	}

	conn, err := net.DialTCP(TYPE, nil, tcpServer)
	if err != nil {
		println("Dial Failed:", err.Error())
		os.Exit(1)
	}

	_, err = conn.Write([]byte("Message Here"))
	if err != nil {
		println("Write Data Failed:", err.Error())
		os.Exit(1)
	}

	// Buffer to Get Data
	recv := make([]byte, 1024)

	_, err = conn.Read(recv)

	if err != nil {
		println("Read Data Failed:", err.Error())
		os.Exit(1)
	}

	println("Received Message:", string(recv))

	conn.Close()

}
