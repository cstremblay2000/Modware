/**
 * file:		client.go
 * author:		Chris Tremblay <cst1465@rit.edu>
 * language: 	Go
 * date:		3/27/2023, National Paella Day!
 * description
 * 	The ModwareClient
 */

package main

import (
	"net"
	"os"
	"fmt"
	"log"
	"time"

	"crypto/rsa"
	//"crypto/rand"
	//"crypto/hmac"
)

const (
	HOST = "127.0.0.1"
	PORT = "5020"
	TYPE = "tcp"
	TIMEOUT = 5 * time.Second 
	FILE_PRIV = "./client.private"
	FILE_PUB = "./client.public"
)

var (
	pubKey rsa.PublicKey
	privKey *rsa.PrivateKey
	serverPub rsa.PublicKey
	serverPriv *rsa.PrivateKey
)

/**
 * description:
 * 	Sends a challenge to modware server for it verify it's
 *	identity
 * parameters:
 *	modwareServerConn -> the TCP Connection to the ModwareServer
 */
func attestChallenge( modwareServerConn net.Conn ) (string, error) {
	// create ModwareServerBuffer
	buffer := make( []byte, 1024 )

	// create a unique challenge to for server
	chall, err := MakeChallenge()
	if( err != nil ){
		return "", err
	}
	println( "chall:", chall )

	// encrypt the challenge
	enc_chall, err := RsaEncrypt( serverPub, []byte(chall) )
	if( err != nil ) {
		return "", err
	}

	// write encrypted challenge out to modware server
	fmt.Println( "Sending Challenge" )
	_, err = modwareServerConn.Write( enc_chall )
	if( err != nil ) {
		return "", err
	}

	// wait for server to send back challenge signature
	fmt.Println( "Waiting for challenge signature" )
	modwareServerConn.SetReadDeadline( time.Now().Add( TIMEOUT ) )

	bytesRead, err := modwareServerConn.Read(buffer)
	if( err != nil ) {
		return "", err
	}
	chall_sig := buffer[:bytesRead]
	fmt.Println( "challenge signature:", chall_sig )

	// verify if signature is valid
	err = RsaVerify( serverPub, []byte(chall), chall_sig )
	if( err != nil ) {
		return "", err
	}
	fmt.Println( "signature verified" )
	return chall, nil
}

func forwardModbusPacket( modwareServerConn net.Conn, mbrequest []byte, chall string ) error {
	// calculate HMAC of modbus request
	hmac := HMAC( []byte(chall), mbrequest )
	fmt.Println( "created hmac:", hmac )

	// wrap into struct and send out
	packet := EncapsulatedModbusPacket {
		MbPacket: mbrequest,
		Hmac: hmac,
	}
	fmt.Println( "encapsulated packet", packet )

	// encode packet into byte array
	bytePacket, err := EncapsulatedModbusPacketToBytes( packet )
	if( err != nil ) {
		return err
	}

	// encrypt
	enc_packet, err := RsaEncrypt( serverPub, bytePacket )
	if( err != nil ){
		return err
	}

	fmt.Println( enc_packet )

	return nil
}

func recieveModbusResponse( modwareServerConn net.Conn, chall string ) ([]byte, error ) {

	return nil, nil
}

func handleRequest(conn net.Conn) {
	// Handle Incoming Request(s)
	buffer := make([]byte, 1024)

	bytesRead, err := conn.Read(buffer)
	if err != nil {
		log.Fatal(err)
	}
	mbrequest := buffer[:bytesRead]
	fmt.Println( "Modbus request:", mbrequest )

	// open connection to ModwareServer and send
	fmt.Println( "connecting to:", conn.RemoteAddr() )
	modwareServerAddr, err := net.ResolveTCPAddr( TYPE, "127.0.0.1:5021" )
	if( err != nil ) {
		fmt.Println( "Error Resolving TCP Addr", err )
		return
	}

	//modwareServerConn, err := net.DialTCP( TYPE, nil, conn.RemoteAddr().(*net.TCPAddr) )
	modwareServerConn, err := net.DialTCP( TYPE, nil, modwareServerAddr )
	if( err != nil ) {
		fmt.Println( "Error Dialing Addr", modwareServerAddr, err )
		return
	}

	// perform attestation with challenge
	fmt.Println( "Starting attestation challenge" )
	chall, err := attestChallenge( modwareServerConn )
	if( err != nil ){
		fmt.Println( "Error attesting challenge", err.Error() )
		modwareServerConn.Close()
		return
	}
	fmt.Println( "Attestation Succeeded")

	// forware modbus request along
	fmt.Println( "Forwarding Modbus Request")
	err = forwardModbusPacket( modwareServerConn, mbrequest, chall )
	if( err != nil ){
		fmt.Println( "Error forwarding modbus request", err )
		modwareServerConn.Close()
		return
	}
	fmt.Println( "Forwarding Modbus Request Succeeded")

	// wait for a response packet
	fmt.Println( "Waiting for Response" )
	mbresp, err := recieveModbusResponse( modwareServerConn, chall )
	if( err != nil ) {
		fmt.Println( "Error recieving packet", err )
		modwareServerConn.Close()
		return 
	}
	fmt.Println( "Successfully recieved mb response", mbresp )

	modwareServerConn.Close()
}

/**
 * description:
 * 	the driver function
 */
func main() {
	var err error

		// get public and private keys
	pubKey, privKey, err = LoadKeys( FILE_PUB, FILE_PRIV )
	if( err != nil ) {
		println( "Couldn't load public/private keys:", err.Error() )
		os.Exit(1)
	}

	serverPub, serverPriv, err = LoadKeys( "./server.public", "./server.private" )
	if( err != nil ) {
		println( "Couldn't load public/private keys:", err.Error() )
		os.Exit(1)
	}

	// create tcp connection to modbus/tcp device
	// and wait for data
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
