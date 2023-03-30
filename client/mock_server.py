import socket
import paramiko
import gob
import io

from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64

def rsaEncrypt( pubKey, plaintext ):
    """
    """
    return pubKey.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsaDecrypt( privKey, ciphertext ):
    """
    """
    return privKey.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsaSign( privKey, message ):
    """
    """
    return privKey.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def rsaVerify( pubKey, message, signature ):
    """
    """
    try:
        pubKey.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except:
        return False
    return True

# Define the Go struct in Python
class EncapsulatedModbusPacket:
    def __init__(self, mb_packet=None, hmac=None):
        self.mb_packet = mb_packet
        self.hmac = hmac

def main():
    """
    """
    HOST = "127.0.0.1"
    PORT = 5021

    clientPubData = None
    with open( "./client.public", "rb" ) as f:
        clientPubData = f.read()
    clientPub = serialization.load_pem_public_key( clientPubData )

    privKeyData = None
    with open( "./server.private", "rb" ) as f:
        privKeyData = f.read()
    privKey = serialization.load_pem_private_key( privKeyData, password=None )

    pubKeyData = None
    with open( "./server.public", "rb" ) as f:
        pubKeyData = f.read()
    pubKey = serialization.load_pem_public_key( pubKeyData )

    print( clientPub )
    print( privKey )
    print( pubKey )

    with socket.socket( socket.AF_INET, socket.SOCK_STREAM ) as s:
        # accept connection
        print( "[mock server] binding" )
        s.bind( (HOST,PORT) )
        print( "[mock server] listening" )
        s.listen()
        conn, addr = s.accept()
        print( "[mock server] accepted", addr )

        # receive challenge
        enc_chall = conn.recv( 1024 )
        print( "[mock server] recieved", enc_chall )

        # decrypt challenge
        chall = rsaDecrypt( privKey, enc_chall )
        print( "[mock server] type", type( chall ) )

        # sign challenge
        signed_chall = rsaSign( privKey, chall )
        print( "[mock server] signed chall", len( signed_chall ), type( signed_chall), signed_chall )

        # encrypt it
        print( "[mock server] sending challenge signature")
        conn.send( signed_chall )

        # wait for packet
        print( "[mock server] waiting for encrypted encapsulated mb request" )
        enc_encap_mb_req = conn.recv( 1024 )

        # decrypt encapsulated modbus request
        encap_mb_req = rsaDecrype( serverPriv, enc_encap_mb_req )
        print( "[mock server] decrypted encapsulated mb request", encap_mb_req )
        
        # encrypt packet and send it back to mimic a write coil request
        enc = rsaEncrypt( clientPub, encap_mb_req )
        conn.write( enc )
        
        while( True ):
            pass

        conn.close()
    return

if( __name__ == "__main__" ):
   main()
