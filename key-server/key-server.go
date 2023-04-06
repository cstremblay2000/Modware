package main 

import (
	"net"
	"fmt"
	"os"
	"log"
)

const (
	// server socket variables
	HOST = "localhost"
	PORT = "5021"
	TYPE = "tcp"
)

/**
 * description
 *	log function that prints things nicely
 * parameters:
 * 	msg -> the message to print
 */
func printLog( msg string ) {
	fmt.Println( "[key-server]", msg )
}

/**
 * description:
 *	the protocol implementation that given a client
 *	the public key for a server
 * parameters:
 *	conn -> the connection to the client
 * 	serverIP -> the IP of the server
 */
func givePublicKey( conn net.Conn, serverIP string ) {
	printLog( "distributing public key" )
}

/**
 * description:
 *	handle a connection from a client
 * parameters:
 *	conn -> the connection to a client
 */
func handleRequest( conn net.Conn ) {
	// check which host this came from

	// decrypt payload

	// see if it is a public key request (should be)

	conn.Close()
}

/**
 * description:
 * 	driver fuction
 */
func main() {
	// start server socket
	listen, err := net.Listen(TYPE, HOST+":"+PORT)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	printLog( "socket listening" )


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