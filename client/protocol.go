package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"crypto/rand"
	"encoding/pem"
	"crypto/sha256"
	"crypto/hmac"

	"math"
	"math/big"
	mrand "math/rand"

	"io/ioutil"
	"errors"

	"bytes"
	"encoding/gob"

	"strconv"
)

/**
 * description:
 * 	struct definition for encapsulating a modbus packet and HMAC
 *	to send over the network
 */
type EncapsulatedModbusPacket struct {
	MbPacket []byte
	Hmac []byte
}

/**
 * description:
 *	The struct that is used by the KeyServer to send
 *	the ModwareServer the challenge and public key
 *	of a ModwareClient
 */
type KeyServerChallengePublicKey struct {
	PublicKey rsa.PublicKey
	Chall []byte
}

/**
 * descriptoin:
 *	simple struct used by ModwareClient to encapsulate 
 *	the IP and MAC address in a packet
 */
type VerifyHostIpMac struct {
	Ip string
	Mac string
}

/**
 * description:
 *	the struct sent to the ModwareClient
 *	that contains the public key of the ModwareServer
 *	it is trying to communicate with 
 *	in the VerifyHost flow
 */
 type KeyServerToModwareClient struct {
	PublicKey rsa.PublicKey
	Chall     []byte
	SigChall  []byte
	SigKS     []byte
}

/**
 * description:
 *	Take an the KeyServerToModwareClient struct and convert it to bytes
 * parameteres:
 * 	packetStruct -> the struct
 * returns:
 *	the gob encoded byte array
 */
 func KeyServerToModwareClientToBytes( packetStruct KeyServerToModwareClient ) ( []byte, error ) {
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
 *	Take bytes and decode it to KeyServerToModwareClient struct 
 * parameteres:
 * 	bytes -> the struct
 * returns:
 *	the KeyServerToModwareClient struct
 */
func KeyServerToModwareClientFromBytes(b []byte) (*KeyServerToModwareClient, error) {
    buf := bytes.NewBuffer(b)
    dec := gob.NewDecoder(buf)
    em := &KeyServerToModwareClient{}
    err := dec.Decode(em)
    if err != nil {
        return nil, err
    }
    return em, nil
}

/**
 * description:
 *	Take an the EncapsulatedModbusPacket struct and convert it to bytes
 * parameteres:
 * 	packetStruct -> the struct
 * returns:
 *	the gob encoded byte array
 */
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
 *	Take bytes and decode it to EncapsulatedModbusPacket struct 
 * parameteres:
 * 	bytes -> the struct
 * returns:
 *	the EncapsulatedModbusPacket struct
 */
func DecodeEncapsulatedModbusPacketFromBytes(b []byte) (*EncapsulatedModbusPacket, error) {
    buf := bytes.NewBuffer(b)
    dec := gob.NewDecoder(buf)
    em := &EncapsulatedModbusPacket{}
    err := dec.Decode(em)
    if err != nil {
        return nil, err
    }
    return em, nil
}

/**
 * description:
 *	Take an the EncapsulatedModbusPacket struct and convert it to bytes
 * parameteres:
 * 	packetStruct -> the struct
 * returns:
 *	the gob encoded byte array
 */
 func VerifyHostKeyServerChallPublicKeyToBytes( packetStruct KeyServerChallengePublicKey ) ( []byte, error ) {
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
 *	Take bytes and decode it to EncapsulatedModbusPacket struct 
 * parameteres:
 * 	bytes -> the struct
 * returns:
 *	the EncapsulatedModbusPacket struct
 */
func DecodeVerifyHostKeyServerChallPublicKeyFromBytes(b []byte) (*KeyServerChallengePublicKey, error) {
    buf := bytes.NewBuffer(b)
    dec := gob.NewDecoder(buf)
    em := &KeyServerChallengePublicKey{}
    err := dec.Decode(em)
    if err != nil {
        return nil, err
    }
    return em, nil
}

/**
 * description:
 *	Take an the EncapsulatedModbusPacket struct and convert it to bytes
 * parameteres:
 * 	packetStruct -> the struct
 * returns:
 *	the gob encoded byte array
 */
 func EncodeVerifyHostIpMacToBytes( packetStruct VerifyHostIpMac ) ( []byte, error ) {
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
 *	Take bytes and decode it to EncapsulatedModbusPacket struct 
 * parameteres:
 * 	bytes -> the struct
 * returns:
 *	the EncapsulatedModbusPacket struct
 */
func DecodeVerifyHostIpMacFromBytes(b []byte) (*VerifyHostIpMac, error) {
    buf := bytes.NewBuffer(b)
    dec := gob.NewDecoder(buf)
    em := &VerifyHostIpMac{}
    err := dec.Decode(em)
    if err != nil {
        return nil, err
    }
    return em, nil
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
 *	Get the public key associated with the client
 * parameters:
 *	filepath -> the IP address of the cleint we are communicating wiht
 * returns:
 *	the public key, or an error upon an error
 */
 func LoadPublicKey( filepath string ) (rsa.PublicKey, error ) {
	pubKeyData, err := ioutil.ReadFile( filepath )
	if err != nil {
		return rsa.PublicKey{}, err
	}
	block, _ := pem.Decode(pubKeyData)
	if block == nil {
		return rsa.PublicKey{}, err
	}
	if block.Type != "PUBLIC KEY" {
		return rsa.PublicKey{}, err
	}

	pKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return rsa.PublicKey{}, err
	}
	return *pKey.(*rsa.PublicKey), nil
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
 func RsaSign(privKey *rsa.PrivateKey, message []byte, chall...byte ) ([]byte, error) {
	hashed := sha256.Sum256( message )
	if( len(chall) == 0 ){
		return rsa.SignPSS(
			rand.Reader,
			privKey,
			crypto.SHA256,
			hashed[:],
			nil,
		)
	} 
	seed, err := strconv.Atoi( string(chall) )
	if( err != nil ){
		return nil, err
	}
	return rsa.SignPSS(
		mrand.New(mrand.NewSource(int64(seed))),
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

/**
 * description:
 *	Take a keyed hash of a byte array
 * parameters:
 *	key -> the key for the HMAC
 *	message -> the message for the HMAC
 * returns:
 *	the HMAC with the given key and message
 */
func HMAC( key, message []byte ) ( []byte ) {
	h := hmac.New(sha256.New, key)
    h.Write(message)

	// Get the HMAC as a byte slice
	return h.Sum(nil)
}

/**
 * description:
 *	just a wrapper function so you don't have to include
 *	extra stuff in your file
 * returns:
 *	true -> if macs are same
 *	false -> otherwise
 */
func SameHMAC( mac1, mac2 []byte ) bool {
	return hmac.Equal( mac1, mac2 )
}

/**
 * description
 * 	creates a unique challenge
 * returns:
 *	The challenge 
 */
func MakeChallenge() (string, error) {
	bChall, err := rand.Int( rand.Reader, big.NewInt(math.MaxInt64) )
	if( err != nil ) {
		return "", err
	}
	return bChall.String(), nil
}