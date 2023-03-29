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
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"crypto/rand"
	"crypto/sha256"

	"math"
	"math/big"

	"net"
	"os"
	"fmt"
	"errors"
	"io/ioutil"
	"log"
	//"time"
)

const (
	HOST = "127.0.0.1"
	PORT = "5020"
	TYPE = "tcp"
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
 * 	Loads public key and private key from a file
 * parameters:
 * 	pubKeyPath -> the path to the public key file
 * 	privKeyPath -> the path to the private key
 * Returns:
 * 	The public key, private key, error condition
 */

 func loadKeys(pubKeyFile, privateKeyFile string) (rsa.PublicKey, *rsa.PrivateKey, error) {
	pubKeyData, err := ioutil.ReadFile(pubKeyFile)
	if err != nil {
		return rsa.PublicKey{}, nil, err
	}
	block, _ := pem.Decode(pubKeyData)
	if block == nil {
		return rsa.PublicKey{}, nil, errors.New("failed to decode public key PEM block")
	}
	if block.Type != "PUBLIC KEY" {
		return rsa.PublicKey{}, nil, errors.New("unsupported public key type")
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return rsa.PublicKey{}, nil, err
	}

	privateKeyData, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return rsa.PublicKey{}, nil, err
	}
	block, _ = pem.Decode(privateKeyData)
	if block == nil {
		return rsa.PublicKey{}, nil, errors.New("failed to decode private key PEM block")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return rsa.PublicKey{}, nil, err
	}

	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return rsa.PublicKey{}, nil, errors.New("unsupported private key type")
	}

	return *pubKey.(*rsa.PublicKey), rsaPrivateKey, nil
}

/**
 * description:
 *	encrypt a plaintext with RSA
 * parameters:
 *	pubKey -> the public key of the resource to communicate with
 *	plaintext -> the plaintext to be encrypt
 * returns:
 * 	The ciphertext
 */
func rsaEncrypt(pubKey rsa.PublicKey, plaintext []byte) ([]byte, error) {
	return rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		&pubKey,
		plaintext,
		nil,
	)
}

/**
 * description:
 *	decrypt a plaintext with RSA
 * parameters:
 *	privKey -> the private key loaded in from file
 *	ciphertext -> the cipher text to decrypt
 * returns:
 * 	The plaintext
 */
func rsaDecrypt(privKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	return rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		privKey,
		ciphertext,
		nil,
	)
}

/**
 * description:
 *	Sign a message with client private key
 * parameters:
 *	privKey -> the private key from client
 *	message -> the message to sign
 * returns:
 * 	The signature
 */
func rsaSign(privKey *rsa.PrivateKey, message []byte) ([]byte, error) {
	hashed := sha256.Sum256( message )
	return rsa.SignPSS(
		rand.Reader,
		privKey,
		crypto.SHA256,
		hashed[:],
		nil,
	)
}

/**
 * description:
 *	Verify a message with resources public key
 * parameters:
 *	pubKey -> public key of the resource to talk to 
 *	message -> the message that was signed
 * 	signature -> the signature of the message
 * returns:
 * 	nil if nothing bad happened
 */
 func rsaVerify(pubKey rsa.PublicKey, message []byte, signature []byte) error {
	hashed := sha256.Sum256(message)
	return rsa.VerifyPSS(
		&pubKey,
		crypto.SHA256,
		hashed[:],
		signature,
		nil,
	)
}

/**
 * description:
 * 	A test suite of crypto functions
 */
func testCrypto( pubKey rsa.PublicKey, privKey *rsa.PrivateKey ) {
	fmt.Println( "public key =", pubKey )
	println()
	fmt.Println( "private key=", privKey )
	println()

	message := "hello, world!"
	enc_message, err := rsaEncrypt( pubKey, []byte(message) )
	if( err != nil ) {
		println( "error encrypting:", err.Error() )
		os.Exit(1)
	}

	signature, err := rsaSign( privKey, []byte(message) )
	if( err != nil ) {
		println( "error signing message:", err.Error() )
		os.Exit(1)
	}
	fmt.Println( "encrypt(", message, ") =", enc_message )
	println()
	fmt.Println( "sign(", message, ") =", signature )
	println()

	dec_message, err := rsaDecrypt( privKey, enc_message )
	if( err != nil ) {
		println( "Error decrypting:", err.Error() )
		os.Exit(1)
	}
	fmt.Println( "decrypted =", string(dec_message[:]) )
	println()

	err = rsaVerify( pubKey, []byte(message), signature )
	if( err != nil ) {
		println( "error verifying signature:", err.Error() )
		os.Exit(1)
	} else {
		println( "Signature was verified" )
	}
	println()
}

func handleRequest(conn net.Conn) {
	// Handle Incoming Request(s)
	buffer := make([]byte, 2048)
	fmt.Println( "IP Addr:", conn.RemoteAddr() ) 

	bytesRead, err := conn.Read(buffer)
	if err != nil {
		log.Fatal(err)
	}

	// Write Incoming Data to Response
	fmt.Println( bytesRead, buffer )

	// create a unique challenge to for server
	chall, err := rand.Int( rand.Reader, big.NewInt(math.MaxInt64) )
	if( err != nil ) {
		log.Fatal( err )
	}
	println( "chall:", chall )

	// encrypt the challenge
	enc_chall, err := rsaEncrypt( pubKey, []byte(chall) )
	if( err != nil ) {
		log.Fatal( err )
	}

	// open connection to ModwareServer and send
	ModwareServer, err := net.ResolveTCPAddr( TYPE, conn.RemoteAddr() )
	if( err != nil ) {
		log.Fatal( err )
	}

	modwareServerConn, err := net.DialTCP( TYPE, nil, ModwareServer )
	if( err != nil ) {
		log.Fatal( err )
	}

	// write encrypted challenge out to modware server
	_, err = modwareServerConn.Write( []byte(enc_chall) )
	if( err != nil ) {
		log.Fatal( err )
	}

	// wait for server to send back signed message
}

/**
 * description:
 * 	the driver function
 */
func main() {
	// init RNG seed

	// get public and private keys
	pubKey, privKey, err := loadKeys( FILE_PUB, FILE_PRIV )
	if( err != nil ) {
		println( "Couldn't load public/private keys:", err.Error() )
		os.Exit(1)
	}
	testCrypto( pubKey, privKey )

	serverPub, serverPriv, err := loadKeys( "./server.public", "./server.private" )
	if( err != nil ) {
		println( "Couldn't load public/private keys:", err.Error() )
		os.Exit(1)
	}
	testCrypto( serverPub, serverPriv )

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
