/**
 * file:		client.go
 * author:		Mohammad Eshan <me3031@rit.edu>
 *				Chris Tremblay <cst1465@rit.edu>
 * language: 	Go
 * date:		4/19/2023, National Garlic Day!
 * description
 * 	The KeyServer
 */

package main

import (
	//"crypto/rsa"
	"fmt"
	"log"
	"net"
	//"os"
	//"path/filepath"
	//"strings"
)

const (
	keyDir       	= "./keys/"
	pubKeyExtension = ".public"
	privKeyExtension= ".private"
	HOST         	= "localhost"
	PORT         	= "5023"
	TYPE         	= "tcp"
)

/**
 * description:
 *	print a log message with a key-server tag
 */
func printLog(msg string) {
	fmt.Println("[key-server]", msg)
}

/**
 * description:
 * 
 * parameters:
 *	modwareServerIP -> the IP address of the ModwareServer
 *	modwareClientIP -> the IP address of the ModwareClient, for key storage
 *	chall -> the unique challenge  
 * returns:
 *	nil -> upon success
 *	error -> otherwise
 */
func givePublicKey( modwareServerIP string, modwareClientIP string, chall string ) error {
	// get ModwareServer public key for encryption
	modwareServerPubKey, err := LoadPublicKey(
		keyDir + modwareServerIP + pubKeyExtension,
	)
	if( err != nil ) {
		fmt.Println( "error getting ModwareServer public and private keys", err )
		return err 
	}

	// get ModwareClient public key to give to ModwareServer
	modwareClientPubKey, err := LoadPublicKey (
		keyDir + modwareClientIP + pubKeyExtension,
	)
	if( err != nil ) {
		fmt.Println( "error getting ModwareClient public and private keys", err )
		return err
	}

	// encrypt challenge
	encryptedChallenge, err := RsaEncrypt(modwareServerPubKey, []byte(chall))
	if err != nil {
		log.Printf("Error encrypting challenge: %v", err)
		return err
	}

	// create struct
	encPacket := EncryptedPacket{
		Challenge: encryptedChallenge,
		Pmc:       modwareClientPubKey,
	}

	// encode packet to bytes
	encPacketBytes, err := encryptedPacketToBytes(encPacket)
	if err != nil {
		log.Printf("Error encoding encrypted packet: %v", err)
		return err
	}

	// connect to ModwareServer
	modwareServerAddr, err := net.ResolveTCPAddr( TYPE, modwareServerIP + ":5022" )
	if err != nil {
		fmt.Println( "error resolving address for ModwareServer", err )
		return err
	}
	modwareServerConn, err := net.DialTCP( TYPE, nil, modwareServerAddr )
	if err != nil {
		fmt.Println( "error dialing ModwareServer", err )
		return err
	}

	// send to ModwareServer
	_, err = modwareServerConn.Write(encPacketBytes)
	if err != nil {
		log.Printf("Error sending encrypted packet: %v", err)
		modwareServerConn.Close()
		return err
	}
	modwareServerConn.Close()
	log.Printf("Sent encrypted challenge and public key for IP: %s\n", modwareServerIP)
	return nil
}

/**
 * description:
 *	the key server side implementation for the verify host protocol flow
 *	
 *	1) a unique challenge is generated by KeyServer
 *	2) the KeyServer loads the stored secret key of the ModwareServer
 *	   that the ModwareClient wants to talk to
 *	3) the KeyServer uses the ModwareServer secret key to sign the challenge
 *	4) the KeyServer then signs the ModwareServer signature of the challenge
 *	5) the data is packaged into a struct, encoded to bytes, encrypted then sent
 * parameters:
 *	modwareClientConn -> the connection to the ModwareClient
 *	pubKeyModwareServer -> the public key of the ModwareServer
 *	ip -> the of the ModwareServer
 *	privKeyServer -> the private key of the ModwareServer
 *	pubKeyCleint -> the public key of the client 
 * returns:
 *	nil -> upon sucess
 *	error -> otherwise
 */
func sendEncryptedPublicKey( 
	modwareClientConn net.Conn,
	modwareServerIP string, 
	modwareClientIP string,
	chall string,
) error {
	// get ModwareServer public key for encryption
	modwareServerPubKey, modwareServerPrivKey, err := LoadKeys(
		keyDir + modwareServerIP + pubKeyExtension,
		keyDir + modwareServerIP + privKeyExtension,
	)
	if( err != nil ) {
		fmt.Println( "error getting ModwareServer public and private keys", err )
		return err 
	}

	// get ModwareClient public key to give to ModwareServer
	modwareClientPubKey, _, err := LoadKeys (
		keyDir + modwareClientIP + pubKeyExtension,
		keyDir + modwareClientIP + privKeyExtension,
	)
	if( err != nil ) {
		fmt.Println( "error getting ModwareClient public and private keys", err )
		return err
	}

	// sign challenge with the stored secret key of the
	// ModwareServer the ModwareClient is trying to talk to
	sigChall, err := RsaSign(modwareServerPrivKey, []byte(chall))
	if err != nil {
		log.Printf("Error signing challenge: %v", err)
		return err
	}

	// have the KeyServer sign the ModwareServer challenge signature
	sigKS, err := RsaSign(privKey, sigChall)
	if err != nil {
		log.Printf("Error signing sigChall: %v", err)
		return err
	}

	// create struct of data to send
	dataToSend := KeyServerToModwareClient {
		PublicKey: modwareServerPubKey,
		Chall:     []byte(chall),
		SigChall:  sigChall,
		SigKS:     sigKS,
	}

	// encode struct to bytes
	encodedDataToSend, err := KeyServerToModwareClientToBytes( dataToSend )
	if err != nil {
		log.Printf("Error encoding struct to bytes: %v", err)
		return err
	}

	// encrypt the bytes and send
	encryptedDataToSend, err := RsaEncrypt( modwareClientPubKey, encodedDataToSend )
	if err != nil {
		log.Printf( "Error encrypting packet: %v", err )
		return err 
	}
	_, err = modwareClientConn.Write(encryptedDataToSend)
	if err != nil {
		log.Printf("Error sending encrypted data: %v", err)
		return err
	}

	// done
	log.Printf("Sent encrypted public key, challenge, and signatures for IP: %s\n", modwareServerIP)
	return nil
}

/**
 * description
 *	handle an incoming request
 *	should only ever be a ModwareClient
 * parameters:
 *	conn -> the connection to the ModwareClient (allegedly)
*	keyStorage -> the in-memory ip to public key storage
 */
func handleRequest(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 1024)

	// read request from ModwareClient
	reqLen, err := conn.Read(buf)
	if err != nil {
		log.Printf("Error reading from connection: %v", err)
		return
	}
	request := string(buf[:reqLen])

	// decode request to get ModwareServer IP and MAC
	decodedRequest, err := ModwareClientToKeyServerFromBytes( request )
	if err != nil {
		fmt.Println( "Error decoding request to IP and MAC:", err )
		conn.Close()
		return
	}

	// create challenge 
	chall, err := MakeChallenge()
	if err != nil {
		fmt.Println( "error creating challenge", err )
		conn.Close() 
		return
	}

	// send packet to ModwareClient
	err = sendEncryptedPublicKey( conn, decodedRequest.Ip, chall )
	if err != nil {
		fmt.Println( "error sending packet to client", err )
		conn.Close()
		return
	}

	// send packet to ModwareServer

	if err != nil {
		log.Printf("Error handling request '%s': %v", request, err)
	}
	conn.Close()
}

/**
 * description:
 *	The driver function for the program
 */
func main() {
	listener, err := net.Listen(TYPE, HOST+":"+PORT)
	if err != nil {
		log.Fatalf("Error listening on %s:%s: %v", HOST, PORT, err)
	}
	defer listener.Close()

	printLog("socket listening")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		go handleRequest(conn)
	}
}