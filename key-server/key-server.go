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
	"crypto/rsa"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
)

const (
	keyDir       = "keys"
	keyExtension = ".pem"
	HOST         = "localhost"
	PORT         = "5023"
	TYPE         = "tcp"
)

type KeyStorage struct {
	keys map[string]*rsa.PublicKey
}

func NewKeyStorage() *KeyStorage {
	return &KeyStorage{keys: make(map[string]*rsa.PublicKey)}
}

func (ks *KeyStorage) AddKey(ip string, key *rsa.PublicKey) {
	ks.keys[ip] = key
}

func (ks *KeyStorage) GetKey(ip string) (*rsa.PublicKey, bool) {
	key, ok := ks.keys[ip]
	return key, ok
}

func printLog(msg string) {
	fmt.Println("[key-server]", msg)
}

/*
func sendEncryptedResponse( 
		conn net.Conn, 
		pubKeyModwareServer *rsa.PublicKey, 
		ip string, 
		privKeyServer *rsa.PrivateKey, 
		pubKeyClient *rsa.PublicKey,
	) error {
	// generate unique challenge for ModwareServer to sign
	challenge, err := MakeChallenge()
	if err != nil {
		log.Printf("Error making challenge: %v", err)
		return err
	}

	// have the stored key for the ModwareServer sign the challenge
	sigChall, err := RsaSign(privKeyServer, []byte(challenge))
	if err != nil {
		log.Printf("Error signing challenge: %v", err)
		return err
	}

	// have the KeyServer sign the ModwareServer challenge signature
	sigKS, err := RsaSign(privKeyServer, sigChall)
	if err != nil {
		log.Printf("Error signing sigChall: %v", err)
		return err
	}

	// create packet to send to ModwareClient
	dataToSend := KeyServerToModwareClient {
		PublicKey: *pubKeyModwareServer,
		Chall:     []byte(challenge),
		SigChall:  sigChall,
		SigKS:     sigKS,
	}

	// encode struct to Bytes, encrypt and send
	encodedDataToSend, err := KeyServerToModwareClientToBytes( dataToSend )
	if( err != nil ) {
		log.Printf( "Error encoding struct to bytes: %v", err )
		return err
	}

	// encrypt packet
	encryptedDataToSend, err := RsaEncrypt(*pubKeyClient, encodedDataToSend )
	if err != nil {
		log.Printf("Error encrypting data to send: %v", err)
		return err
	}

	_, err = conn.Write(encryptedDataToSend)
	if err != nil {
		log.Printf("Error sending encrypted data: %v", err)
		return err
	}

	log.Printf("Sent encrypted public key, challenge, and signatures for IP: %s\n", ip)
	return nil
}*/

func givePublicKey(conn net.Conn, keyStorage *KeyStorage) error {
	ip := conn.RemoteAddr().(*net.TCPAddr).IP.String()

	pubKeyModwareServer, ok := keyStorage.GetKey(ip)
	if !ok {
		log.Printf("No public key found for IP: %s\n", ip)
		return fmt.Errorf("no public key found for IP: %s", ip)
	}

	pubKeyClient, ok := keyStorage.GetKey(ip) // Assuming the client's public key is stored in the keyStorage
	if !ok {
		log.Printf("No client public key found for IP: %s\n", ip)
		return fmt.Errorf("no client public key found for IP: %s", ip)
	}

	// Replace the following line with the path to the key server's private key file
	privKeyServerPath := "path/to/key_server_private_key.pem"

	_, privKeyServer, err := LoadKeys("", privKeyServerPath)
	if err != nil {
		log.Printf("Error loading key server private key: %v", err)
		return err
	}

	err = sendEncryptedPublicKey(conn, pubKeyModwareServer, ip, privKeyServer, pubKeyClient)
	if err != nil {
		log.Printf("Error sending encrypted public key: %v", err)
		return err
	}

	return nil
}

func handleRequest(conn net.Conn, keyStorage *KeyStorage) {
	defer conn.Close()

	err := givePublicKey(conn, keyStorage)
	if err != nil {
		log.Printf("Error giving public key: %v", err)
	}
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
 *	conn -> the connection to the ModwareClient
 *	pubKeyModwareServer -> the public key of the ModwareServer
 *	ip -> the ip of the client?
 *	privKeyServer -> the private key of the ModwareServer
 *	pubKeyCleint -> the public key of the client 
 * returns:
 *	nil -> upon sucess
 *	error -> otherwise
 */
func sendEncryptedPublicKey(
		conn net.Conn, 
		pubKeyModwareServer *rsa.PublicKey, 
		ip string, 
		privKeyServer *rsa.PrivateKey, 
		pubKeyClient *rsa.PublicKey,
	) error {
	// create unique challenge
	challenge, err := MakeChallenge()
	if err != nil {
		log.Printf("Error making challenge: %v", err)
		return err
	}

	// sign challenge with the stored secret key of the
	// ModwareServer the ModwareClient is trying to talk to
	sigChall, err := RsaSign(privKeyServer, []byte(challenge))
	if err != nil {
		log.Printf("Error signing challenge: %v", err)
		return err
	}

	// have the KeyServer sign the ModwareServer challenge signature
	sigKS, err := RsaSign(privKeyServer, sigChall)
	if err != nil {
		log.Printf("Error signing sigChall: %v", err)
		return err
	}

	// create struct of data to send
	dataToSend := KeyServerToModwareClient {
		PublicKey: *pubKeyModwareServer,
		Chall:     []byte(challenge),
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
	encryptedDataToSend, err := RsaEncrypt( *pubKeyClient, encodedDataToSend )
	if err != nil {
		log.Printf( "Error encrypting packet: %v", err )
		return err 
	}
	_, err = conn.Write(encryptedDataToSend)
	if err != nil {
		log.Printf("Error sending encrypted data: %v", err)
		return err
	}

	// done
	log.Printf("Sent encrypted public key, challenge, and signatures for IP: %s\n", ip)
	return nil
}

/**
 * description:
 *	The driver function for the program
 */
func main() {
	keyStorage := NewKeyStorage()

	err := filepath.Walk(keyDir, func(path string, info os.FileInfo, err error) error {
		if( info == nil ) {
			return nil
		}
		if !info.IsDir() && strings.HasSuffix(path, keyExtension) {
			ip := strings.TrimSuffix(info.Name(), keyExtension)
			pubKey, err := LoadPublicKey(path)
			if err != nil {
				return err
			}
			keyStorage.AddKey(ip, &pubKey)
			fmt.Printf("Loaded key for IP: %s\n", ip)
		}
		return nil
	})

	if err != nil {
		log.Fatalf("Error loading keys: %v", err)
	}

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
		go handleRequest(conn, keyStorage)
	}
}
