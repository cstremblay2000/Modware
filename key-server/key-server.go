package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
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
	PORT         = "5020"
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

func LoadPublicKey(pubKeyPath string) (rsa.PublicKey, error) {
	pubKeyData, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		return rsa.PublicKey{}, err
	}
	block, _ := pem.Decode(pubKeyData)
	if block == nil {
		return rsa.PublicKey{}, errors.New("failed to decode public key PEM block")
	}
	if block.Type != "PUBLIC KEY" {
		return rsa.PublicKey{}, errors.New("unsupported public key type")
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return rsa.PublicKey{}, err
	}

	return *pubKey.(*rsa.PublicKey), nil
}

func sendEncryptedResponse(conn net.Conn, pubKeyModwareServer *rsa.PublicKey, ip string, privKeyServer *rsa.PrivateKey, pubKeyClient *rsa.PublicKey) error {
	challenge, err := MakeChallenge()
	if err != nil {
		log.Printf("Error making challenge: %v", err)
		return err
	}

	sigChall, err := RsaSign(privKeyServer, []byte(challenge))
	if err != nil {
		log.Printf("Error signing challenge: %v", err)
		return err
	}

	sigKS, err := RsaSign(privKeyServer, sigChall)
	if err != nil {
		log.Printf("Error signing sigChall: %v", err)
		return err
	}

	dataToSend := struct {
		PublicKey rsa.PublicKey
		Chall     []byte
		SigChall  []byte
		SigKS     []byte
	}{
		PublicKey: *pubKeyModwareServer,
		Chall:     []byte(challenge),
		SigChall:  sigChall,
		SigKS:     sigKS,
	}

	encodedDataToSend, err := RsaEncrypt(*pubKeyClient, dataToSend)
	if err != nil {
		log.Printf("Error encrypting data to send: %v", err)
		return err
	}

	_, err = conn.Write(encodedDataToSend)
	if err != nil {
		log.Printf("Error sending encrypted data: %v", err)
		return err
	}

	log.Printf("Sent encrypted public key, challenge, and signatures for IP: %s\n", ip)
	return nil
}

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

func sendEncryptedPublicKey(conn net.Conn, pubKeyModwareServer *rsa.PublicKey, ip string, privKeyServer *rsa.PrivateKey, pubKeyClient *rsa.PublicKey) error {
	challenge, err := MakeChallenge()
	if err != nil {
		log.Printf("Error making challenge: %v", err)
		return err
	}

	sigChall, err := RsaSign(privKeyServer, []byte(challenge))
	if err != nil {
		log.Printf("Error signing challenge: %v", err)
		return err
	}

	sigKS, err := RsaSign(privKeyServer, sigChall)
	if err != nil {
		log.Printf("Error signing sigChall: %v", err)
		return err
	}

	dataToSend := struct {
		PublicKey rsa.PublicKey
		Chall     []byte
		SigChall  []byte
		SigKS     []byte
	}{
		PublicKey: *pubKeyModwareServer,
		Chall:     []byte(challenge),
		SigChall:  sigChall,
		SigKS:     sigKS,
	}

	encodedDataToSend, err := RsaEncrypt(*pubKeyClient, dataToSend)
	if err != nil {
		log.Printf("Error encrypting data to send: %v", err)
		return err
	}

	_, err = conn.Write(encodedDataToSend)
	if err != nil {
		log.Printf("Error sending encrypted data: %v", err)
		return err
	}

	log.Printf("Sent encrypted public key, challenge, and signatures for IP: %s\n", ip)
	return nil
}

func main() {
	keyStorage := NewKeyStorage()

	err := filepath.Walk(keyDir, func(path string, info os.FileInfo, err error) error {
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
