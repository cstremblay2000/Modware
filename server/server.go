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
	"errors"

	"crypto/rsa"
)

// Define Variables
const (
	HOST = "127.0.0.3"
	PORT = "5020"
	TYPE = "tcp"
	MAC  = "MAC"
	KEYSERVER_HOST = "127.0.0.1"
	KEYSERVER_PORT = "5020"
)

var (
	pubKey rsa.PublicKey
	privKey *rsa.PrivateKey
	LADDR = &net.TCPAddr{IP: net.ParseIP(HOST), Port: 0}
)

/**
 * description:
 *	Remote attestation challenge for server
 *	server recieves the challenge and decrypts it
 *	they sign it and send the encrypted signature back
 * parameters:
 *	modwareClientConn -> socket to ModwareClient
 *	modwareClientPubKey -> tehe ModwareClient public key 
 * returns:
 *	the challenge for later use upons success
 * 	errors otherwise
 */
func attestChallenge( modwareClientConn net.Conn, modwareClientPubKey rsa.PublicKey, recvMsg []byte ) (string, error) {
	// decrypt challenge with our private key
	chall, err := RsaDecrypt( privKey, recvMsg )
	if err != nil {
		fmt.Printf("Failed to decrypt challenge: %v", err)
		return "", err
	}
	fmt.Println( "Decrypted challenge", string(chall) )

	// sign unencrypted challenge with out public key, and write it out
	signedChall, err := RsaSign( privKey, chall )
	if err != nil {
		fmt.Printf("Failed to sign challenge: %v", err)
		return "", err
	}
	fmt.Println( "Signed challenge")

	_, err = modwareClientConn.Write(signedChall)
	if( err != nil ) {
		fmt.Printf("Failed to send Challenge: %v", err)
		return "", err
	}

	return string(chall), nil
}

/**
 * description:
 *	receive a modbus request
 *	decrupt it with our private key
 *	check hmacs are valid
 * 	extract mb request from packet structure
 * parameters:
 *	modwareClientConn -> the socket to the ModwareClient
 *	clientPublicKey -> the public key of the ModwareClient
 *	chall -> the challenge learned through remote attestation
 * returns:
 * 	the modbus request payload upon success
 *	errors otherwize
 */
func recieveModbusRequest( modwareClientConn net.Conn, clientPublicKey rsa.PublicKey, chall string ) ( []byte, error ) {
	// recieve the encapsulated request
	buffer := make([]byte, 1024)
	bytesRead, err := modwareClientConn.Read( buffer )
	if( err != nil ) {
		fmt.Printf("Failed to decrypt challenge: %v\n", err)
		return nil, err
	}
	encPacket := buffer[:bytesRead]
	fmt.Println( "Recieved", bytesRead, "bytes")

	// decrypt packet
	encapPacket, err := RsaDecrypt( privKey, encPacket )
	if( err != nil ) {
		fmt.Printf("Failed to decrypt modbus request: %v", err)
		return nil, err
	}
	fmt.Println( "Decrypted encapsulated packet" )

	// decode packet
	packetStruct, err := DecodeEncapsulatedModbusPacketFromBytes( encapPacket )
	if( err != nil ) {
		fmt.Printf("Failed to decode modbus request: %v", err)
		return nil, err
	}
	fmt.Println( "Decoded", packetStruct.MbPacket, packetStruct.Hmac )

	// verify HMACs
	expectedHMAC := HMAC( []byte(chall), packetStruct.MbPacket )
	if( !SameHMAC( expectedHMAC, packetStruct.Hmac ) ){
		return nil, errors.New( "check HMACs: HMACs are not the same" )
	}

	return packetStruct.MbPacket, nil
}

/**
 * description:
 * 	send the request to the actual server device
 * parameters:
 * 	conn -> the connection to client conn
 *	request -> the Modbus response payload
 * returns:
 *	the modbus reponse upon success
 *	errors upon failure
 */
 func forwardModbusRequest( conn net.Conn, request []byte ) ( []byte, error ) {
	_, err := conn.Write( request )
	if( err != nil ) {
		fmt.Printf( "failed to send modbus request %v\n", err )
		return nil, err 
	}
	fmt.Println( "sent modbus request" )

	// recieve the encapsulated request
	buffer := make([]byte, 1024)
	bytesRead, err := conn.Read( buffer )
	if( err != nil ) {
		fmt.Printf("failed to get modbus resposne: %v\n", err)
		return nil, err
	}
	mbResponse := buffer[:bytesRead]
	fmt.Println( "recieved modbus response" )
	return mbResponse, nil
}

/**
 * description:
 *	Take the modbus response send from the actual server device 
 *	HMAC it and send the HMAC and modbus response back to 
 *	Modware client via public key encryption
 * parameters:
 *	modwareClientConn -> socket to ModwareClient
 *	clientPublicKey -> the public key of the ModwareClient
 *	chall -> the challenge learned from remote attestation previously
 *	mbResponse -> the Modbus resposne from the actual server device
 * returns:
 *	errors upon error
 *	nil upon success
 */
func forwardModbusResponse( modwareClientConn net.Conn, clientPublicKey rsa.PublicKey, chall string, mbResponse []byte ) error {
	// calculate HMAC of modbus request
	hmac := HMAC( []byte(chall), mbResponse )
	fmt.Println( "created hmac:", hmac )

	// wrap into struct and send out
	packet := EncapsulatedModbusPacket {
		MbPacket: mbResponse,
		Hmac: hmac,
	}
	fmt.Println( "encapsulated packet", packet )

	// encode packet into byte array
	bytePacket, err := EncapsulatedModbusPacketToBytes( packet )
	if( err != nil ) {
		fmt.Println( "Error encoding struct to bytes", err )
		return err
	}

	// encrypt
	enc_packet, err := RsaEncrypt( clientPublicKey, bytePacket )
	if( err != nil ){
		fmt.Println( "error encrypting encapsulated modbus packet", err )
		return err
	}
	fmt.Println( "Encrypted packet", enc_packet )

	// send encrypted packet
	_, err = modwareClientConn.Write( enc_packet )
	if( err != nil ) {
		fmt.Println( "Error sending encrypted packet to ModwareClient", err )
		return err
	}
 	fmt.Println( "sent packet" )
	return nil
}

/**
 * description:
 *	begin communication between verified hosts
 * parameters:
 *	conn -> the connection to the ModwareClient
 * 	recvMsg -> the message initially recieved from the ModwareClient
 * returns:
 *	error upon error
 *	nil upon success
 */
func verifiedCommunication( conn net.Conn, recvMsg []byte ) error {
	// get ip of client device
	remoteAddr := conn.RemoteAddr()
    tcpAddr, ok := remoteAddr.(*net.TCPAddr)
    if !ok {
        panic("not a tcp address")
    }
    clientIP := tcpAddr.IP.String()
    fmt.Println("IP address:", clientIP)

	// get public key of client
	clientPublicKey, err := LoadPublicKey( "../client/client.public" )
	if( err != nil ) {
		fmt.Println( "error getting ModwareClient public key", err )
		return err
	}
	fmt.Println( "Get public key for client", clientIP )

	// attest the challenge
	fmt.Println( "Begining to attest challenge" )
	chall, err := attestChallenge( conn, clientPublicKey, recvMsg )
	if( err != nil ) {
		fmt.Println( "error challenge attestation" )
		return err
	}
	fmt.Println( "Successfully attested challenge\n" )

	// get the modbus packet
	fmt.Println( "Beginning modbus request reception" )
	mbRequest, err := recieveModbusRequest( conn, clientPublicKey, chall )
	if( err != nil ) {
		fmt.Println( "error recieving modbus request" )
		return err
	}
	fmt.Println( mbRequest )
	fmt.Println( "Successfully recieved modbus request\n")

	// forward the request to the server device and get response
	fmt.Println( "Beginning forwarding request")
	serverAddr, err := net.ResolveTCPAddr( TYPE, "127.0.0.1:502" )
	if( err != nil ) {
		fmt.Println( "Error Resolving TCP Addr", err )
		return err
	}
	fmt.Println( "dialed server successfully")
	serverConn, err := net.DialTCP( TYPE, LADDR, serverAddr )
	if( err != nil ) {
		fmt.Println( "Error Dialing Addr", serverAddr, err )
		return err
	}
	fmt.Println( "connected to server succesfully" )
	mbResponse, err := forwardModbusRequest( serverConn, mbRequest )
	if( err != nil ) {
		fmt.Println( "error recieving modbus request" )
		return err
	}
	fmt.Println( mbResponse )
	fmt.Println( "Successfully forward request\n")

	// forward response back to client
	fmt.Println( "forwarding response back to client")
	err = forwardModbusResponse( conn, clientPublicKey, chall, mbResponse )
	if err != nil {
		fmt.Println( "error forwarding response", err )
		return err
	}
	fmt.Println( "forwarded response back to client successfully")

	return nil
}

func verifyHost( modwareClientConn net.Conn ) error {
	// get mac addr
    iface, err := net.InterfaceByName("lo")
    if err != nil {
        fmt.Println(err)
        return err 
    }
	macAddr := iface.HardwareAddr

	fmt.Println( "sending MAC addr", macAddr )
	_, err = modwareClientConn.Write( []byte("00:00:00:00:00:00") )
	if err != nil {
		fmt.Println( "error sending mac to ModwareClient")
		return err
	}
	fmt.Println( "mac addr sent" )

	// start up new server socket 
	listen, err := net.Listen(TYPE, HOST+":"+"5021")
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	// listen for requests incoming from KeyServer
	defer listen.Close()
	fmt.Println( "Listening for KeyServer connection")
	keyServerConn, err := listen.Accept()
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	// recieve challenge and client public key from KeyServer
	buffer := make( []byte, 1024 )
	bytesRead, err := keyServerConn.Read( buffer )
	keyServerConn.Close() 
	listen.Close()
	if( err != nil ) {
		fmt.Println( "error getting data from KeyServer", err )
		return err 
	}
	data := buffer[:bytesRead]

	// extract challenge and ModwareClient public key
	packetStruct,err := decodeEncryptedPacketFromBytes( data )
	if( err != nil ) {
		fmt.Println( "Error decapsulating packet",err  )
		return err
	}

	// decrypt the challenge
	chall, err := RsaDecrypt( privKey, packetStruct.Challenge )
	if err != nil {
		fmt.Println( "Error decryptin challenge:", err )
		return err
	}
	fmt.Println( "chall:", string( chall) )

	// sign challenge
	signedChall, err := RsaSign( privKey, chall, chall... )
	fmt.Println( "sigchall", signedChall )
	if( err != nil ) {
		fmt.Println( "Error signing challenge", err )
		return err
	}

	// send challenge out to ModwareClient
	_, err = modwareClientConn.Write( signedChall ) 
	if( err != nil ) {
		fmt.Println( "error sending signed challenge to ModwareClient",err  )
		return err
	}

	// save public key to PEM encoded file
	return nil
}

/**
 * description:
 *	preprocess the request
 * parameters:
 *	conn -> the connection recieved
 */
func handleRequest(conn net.Conn) {
	// check to see if we are being verified
	buffer := make([]byte, 1024)
	bytesRead, err := conn.Read( buffer )
	if( err != nil ) {
		fmt.Println( "error reading message from client")
		conn.Close()
		return 
	}
	recvMsg := buffer[:bytesRead]

	// verify host logic 
	if( string(recvMsg) == MAC ) {
		fmt.Println( "beginning to sent MAC address" )
		err = verifyHost( conn )
		if( err != nil ) {
			fmt.Println( "Error verifying host", err )
			conn.Close()
			return
		}
	}
	
	// continute with verified communication
	err = verifiedCommunication( conn, recvMsg )
	if( err != nil ) {
		fmt.Println( "Error performing secure communciation" )
		conn.Close()
		return
	}

	// Close Connection
	conn.Close()
}

/**
 * description:
 * 	The driver function
 */
func main() {
	// get error keys
	var err error
	pubKey, privKey, err = LoadKeys( "./server.public", "./server.private" )
	if( err != nil ) {
		log.Fatal( err )
		os.Exit( 1 )
	}

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