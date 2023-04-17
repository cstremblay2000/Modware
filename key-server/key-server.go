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

func givePublicKey(conn net.Conn, keyStorage *KeyStorage) error {
	ip := conn.RemoteAddr().(*net.TCPAddr).IP.String()

	pubKey, ok := keyStorage.GetKey(ip)
	if !ok {
		log.Printf("No public key found for IP: %s\n", ip)
		return fmt.Errorf("no public key found for IP: %s", ip)
	}

	challenge, err := MakeChallenge()
	if err != nil {
		log.Printf("Error making challenge: %v", err)
		return err
	}

	packet := KeyServerChallengePublicKey{
		PublicKey: *pubKey,
		Chall:     []byte(challenge),
	}

	packetBytes, err := VerifyHostKeyServerChallPublicKeyToBytes(packet)
	if err != nil {
		log.Printf("Error encoding packet: %v", err)
		return err
	}

	_, err = conn.Write(packetBytes)
	if err != nil {
		log.Printf("Error sending packet: %v", err)
		return err
	}

	log.Printf("Sent challenge and public key for IP: %s\n", ip)
	return nil
}

func handleRequest(conn net.Conn, keyStorage *KeyStorage) {
	defer conn.Close()

	err := givePublicKey(conn, keyStorage)
	if err != nil {
		log.Printf("Error giving public key: %v", err)
	}
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
