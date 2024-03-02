import sys
import socket
from os import _exit as quit
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256

delimiter = b'<<DELIMITER>>'

def hmac_generate(msg, enc=False):
    with open("h_key.bin", "rb") as h:
        h_key = h.read()
    secret_key = HMAC.new(h_key, digestmod=SHA256)
    if enc:
        secret_key.update(msg)
    else:
        secret_key.update(msg.encode('utf-8'))
        
    mac = secret_key.digest() # the tag
    
    return msg, mac

def aes_encrypt(msg):
    a_private_key = RSA.import_key(open("a_private_key.pem").read())
    a_public_key = RSA.import_key(open("a_public_key.pem").read())
    b_public_key = RSA.import_key(open("b_public_key.pem").read())
    
    # open the AES key 
    with open("aes.enc", 'rb') as enc_key:
        aes_key = enc_key.read()

    # Encrypt the AES key with the recipient's public RSA key
    cipher_rsa = PKCS1_OAEP.new(b_public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    
    # Create a new AES cipher in CTR mode
    cipher_aes = AES.new(aes_key, AES.MODE_CTR)
    
    # Encrypt the message
    enc_msg = cipher_aes.encrypt(msg.encode('utf-8'))
    
    # Extract the nonce used for encryption
    iv = cipher_aes.nonce
    
    return enc_msg, encrypted_aes_key, iv


def enc_then_mac_Alice(msg):
    enc_msg, encrypted_aes_key, iv = aes_encrypt(msg)

    enc_msg, mac = hmac_generate(enc_msg, enc=True)

    return mac, enc_msg, encrypted_aes_key, iv

def main():

    # parse arguments
    if len(sys.argv) != 4:
        print("usage: python3 %s <host> <port> <config>" % sys.argv[0]);
        quit(1)
    host = sys.argv[1]
    port = sys.argv[2]
    config = sys.argv[3]

    # open a socket
    clientfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # connect to server
    clientfd.connect((host, int(port)))

    # message loop
    while(True):
        msg = input("Enter message for Bob: ")
        
        if config == "NONE":
            clientfd.send(msg.encode())
            
        elif config == "ENC":
            enc_msg, encrypted_aes_key, iv = aes_encrypt(msg)
            data_to_send = enc_msg + delimiter + encrypted_aes_key + delimiter + iv
            
            clientfd.sendall(data_to_send)
            
        elif config == "MAC":
            msg, mac = hmac_generate(msg)
            data_to_send = msg.encode('utf-8') + delimiter + mac
            
            clientfd.sendall(data_to_send)
            
        elif config == "ENCMAC":
            mac, enc_msg, encrypted_aes_key, iv = enc_then_mac_Alice(msg)
            data_to_send = mac + delimiter + enc_msg + delimiter + encrypted_aes_key  + delimiter + iv
            
            clientfd.sendall(data_to_send)
        

    clientfd.close()

if __name__ == "__main__":
    main()
