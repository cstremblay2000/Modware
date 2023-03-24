package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

// Define Variables
const (
	HOST = "localhost"
	PORT = "8080"
	TYPE = "tcp"
)

func main() {
	listen, err := net.Listen(TYPE, HOST+":"+PORT)

	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	// Close Listener
	defer listen.Close()
	for {
		conn, err := listen.Accept()

		if err != nil {
			log.Fatal(err)
			os.Exit(1)
		}
		go handleRequest(conn)
	}
}

func handleRequest(conn net.Conn) {
	// Handle Incoming Request(s)
	buffer := make([]byte, 1024)

	_, err := conn.Read(buffer)
	if err != nil {
		log.Fatal(err)
	}

	// Write Incoming Data to Response
	time := time.Now().Format(time.ANSIC)
	responseStr := fmt.Sprintf("Your message is: %v. Received time %v", string(buffer[:]), time)
	conn.Write([]byte(responseStr))

	// Close Connection
	conn.Close()

}
