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
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"errors"
	"io/ioutil"
)

const (
	HOST = "localhost"
	PORT = "8080"
	TYPE = "tcp"
	FILE_PRIV = "./client.private"
	FILE_PUB = "./client.public"
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
 func rsaVerify(pubKey *rsa.PublicKey, message []byte, signature []byte) error {
	hashed := sha256.Sum256(message)
	return rsa.VerifyPSS(
		pubKey,
		crypto.SHA256,
		hashed[:],
		signature,
		nil,
	)
}

/**
 * description:
 * 	the driver function
 */
func main() {
	pubKey, privKey, err := loadKeys( FILE_PUB, FILE_PRIV )
	if( err != nil ) {
		println( "Couldn't load public/private keys:", err.Error() )
		os.Exit(1)
	}
	fmt.Println( pubKey )
	fmt.Println( privKey )
	message := "hello, world!"
	enc_message, err := rsaEncrypt( pubKey, []byte(message) )
	if( err != nil ) {
		println( "error encrypting:", err.Error() )
		os.Exit(1)
	}
	signature, err := rsaSign( privKey, enc_message )
	if( err != nil ) {
		println( "error signing message:", err.Error() )
		os.Exit(1)
	}
	fmt.Println( enc_message )
	fmt.Println( signature )

	dec_message, err := rsaDecrypt( privKey, enc_message )
	if( err != nil ) {
		println( "Error decrypting:", err.Error() )
		os.Exit(1)
	}
	fmt.Println( string(dec_message[:]) )

	err = rsaVerify( pubKey, []byte(message), signature )
	if( err != nil ) {
		println( "error verifying signature:", err.Error() )
		os.Exit(1)
	}

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
