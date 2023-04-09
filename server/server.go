/**
 * file:		server.go
 * author:		Chris Tremblay <cst1465@rit.edu>
 * language: 	Go
 * date:		4/8/2023, National Empanada Day!
 * description
 * 	The ModwareServer
 */

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	//"time"
)

// Define Variables
const (
	HOST = "localhost"
	PORT = "5021"
	TYPE = "tcp"
	MAC  = "MAC"
)

func verifyHost() {
	
}

/**
 * description:
 *	preprocess the request
 * parameters:
 *	conn -> the connection recieved
 */
func handleRequest(conn net.Conn) {
	// Handle Incoming Request(s)
	buffer := make([]byte, 1024)
	byteCount, err := conn.Read(buffer)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println( "bytes read", byteCount )

	// check to see if the data is MAC request
	msg := string( buffer[:byteCount] )
	if( msg == MAC ) {
		fmt.Println( "detected MAC" )
	} else {
		fmt.Println( "msg: ", msg )
	}

	// Close Connection
	conn.Close()

}

/**
 * description:
 * 	The driver function
 */
func main() {
	// start a server socket
	listen, err := net.Listen(TYPE, HOST+":"+PORT)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	// handle incoming requests
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