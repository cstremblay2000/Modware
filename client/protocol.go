package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/hmac"

	"math"
	"math/big"

	"io/ioutil"
	"errors"

	"bytes"
	"encoding/gob"
)

type EncapsulatedModbusPacket struct {
	MbPacket []byte
	Hmac []byte
}

func EncapsulatedModbusPacketToBytes( packetStruct EncapsulatedModbusPacket ) ( []byte, error ) {
	buf := new(bytes.Buffer)
    enc := gob.NewEncoder(buf)
    err := enc.Encode(packetStruct)
    if err != nil {
        return nil, err
    }
    return buf.Bytes(), nil
}

/**
 * description:
 * 	Loads public key and private key from a file
 * parameters:
 * 	pubKeyPath -> the path to the public key file
 * 	privKeyPath -> the path to the private key
 * Returns:
 * 	The public key, private key, error condition
 */

 func LoadKeys(pubKeyFile, privateKeyFile string) (rsa.PublicKey, *rsa.PrivateKey, error) {
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
 func RsaEncrypt(pubKey rsa.PublicKey, plaintext []byte) ([]byte, error) {
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
func RsaDecrypt(privKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
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
func RsaSign(privKey *rsa.PrivateKey, message []byte) ([]byte, error) {
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
 func RsaVerify(pubKey rsa.PublicKey, message []byte, signature []byte) error {
	hashed := sha256.Sum256(message)
	return rsa.VerifyPSS(
		&pubKey,
		crypto.SHA256,
		hashed[:],
		signature,
		nil,
	)
}

func HMAC( key, message []byte ) ( []byte ) {
	h := hmac.New(sha256.New, key)
    h.Write(message)

	// Get the HMAC as a byte slice
	return h.Sum(nil)
}

/**
 * description
 * 	creates a unique challenge
 */
func MakeChallenge() (string, error) {
	bChall, err := rand.Int( rand.Reader, big.NewInt(math.MaxInt64) )
	if( err != nil ) {
		return "", err
	}
	return bChall.String(), nil
}