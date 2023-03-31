package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net"
)

func rsaEncrypt(pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, plaintext, nil)
}

func rsaDecrypt(privKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, ciphertext, nil)
}

func rsaSign(privKey *rsa.PrivateKey, message []byte) ([]byte, error) {
	hash := sha256.Sum256(message)
	return rsa.SignPSS(rand.Reader, privKey, crypto.SHA256, hash[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
}

func rsaVerify(pubKey *rsa.PublicKey, message []byte, signature []byte) bool {
	hash := sha256.Sum256(message)
	err := rsa.VerifyPSS(pubKey, crypto.SHA256, hash[:], signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
	return err == nil
}

type EncapsulatedModbusPacket struct {
	mbPacket []byte
	hmac     []byte
}

func main() {
	const (
		host = "127.0.0.1"
		port = 5021
	)

	clientPubData, err := ioutil.ReadFile("./client.public")
	if err != nil {
		log.Fatalf("Failed to read client public key: %v", err)
	}
	clientPubBlock, _ := pem.Decode(clientPubData)
	clientPub, err := x509.ParsePKIXPublicKey(clientPubBlock.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse client public key: %v", err)
	}
	clientRSAPub := clientPub.(*rsa.PublicKey)

	privKeyData, err := ioutil.ReadFile("./server.private")
	if err != nil {
		log.Fatalf("Failed to read server private key: %v", err)
	}
	privKeyBlock, _ := pem.Decode(privKeyData)
	privInterface, err := x509.ParsePKCS8PrivateKey(privKeyBlock.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse server private key: %v", err)
	}
	privKey := privInterface.(*rsa.PrivateKey)

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	conn, err := listener.Accept()
	if err != nil {
		log.Fatalf("Failed to accept connection: %v", err)
	}
	defer conn.Close()

	encChall := make([]byte, 256)
	conn.Read(encChall)

	chall, err := rsaDecrypt(privKey, encChall)
	if err != nil {
		log.Fatalf("Failed to decrypt challenge: %v", err)
	}

	signedChall, err := rsaSign(privKey, chall)
	if err != nil {
		log.Fatalf("Failed to sign challenge: %v", err)
	}

	conn.Write(signedChall)

	encEncapMbReq := make([]byte, 256)
	conn.Read(encEncapMbReq)

	encapMbReq, err := rsaDecrypt(privKey, encEncapMbReq)
	if err != nil {
		log.Fatalf("Failed to decrypt encapsulated Modbus request: %v", err)
	}

	fmt.Printf("Decrypted encapsulated Modbus request: %v\n", encapMbReq)

	enc, err := rsaEncrypt(clientRSAPub, encapMbReq)
	if err != nil {
		log.Fatalf("Failed to encrypt packet: %v", err)
	}

	conn.Write(enc)
}
