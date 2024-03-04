import sys
import socket
from os import _exit as quit
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
import easygui
from dashboard import Dashboard

# delimiter = b'<<DELIMITER>>'

# def hmac_generate(msg, enc=False):
#     with open("h_key.bin", "rb") as h:
#         h_key = h.read()
#     secret_key = HMAC.new(h_key, digestmod=SHA256)
#     if enc:
#         secret_key.update(msg)
#     else:
#         secret_key.update(msg.encode('utf-8'))
        
#     mac = secret_key.digest() # the tag
    
#     return msg, mac

# def aes_encrypt(msg):
#     a_private_key = RSA.import_key(open("a_private_key.pem").read())
#     a_public_key = RSA.import_key(open("a_public_key.pem").read())
#     b_public_key = RSA.import_key(open("b_public_key.pem").read())
    
#     # open the AES key 
#     with open("aes.enc", 'rb') as enc_key:
#         aes_key = enc_key.read()

#     # Encrypt the AES key with the recipient's public RSA key
#     cipher_rsa = PKCS1_OAEP.new(b_public_key)
#     encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    
#     # Create a new AES cipher in CTR mode
#     cipher_aes = AES.new(aes_key, AES.MODE_CTR)
    
#     # Encrypt the message
#     enc_msg = cipher_aes.encrypt(msg.encode('utf-8'))
    
#     # Extract the nonce used for encryption
#     iv = cipher_aes.nonce
    
#     return enc_msg, encrypted_aes_key, iv


# def enc_then_mac_Alice(msg):
#     enc_msg, encrypted_aes_key, iv = aes_encrypt(msg)

#     enc_msg, mac = hmac_generate(enc_msg, enc=True)

#     return mac, enc_msg, encrypted_aes_key, iv

def main():

    # parse arguments
    if len(sys.argv) != 3:
        print("usage: python3 %s <host> <port>" % sys.argv[0]);
        quit(1)
    host = sys.argv[1]
    port = sys.argv[2]

    # # open a socket
    # clientfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # # connect to server
    # clientfd.connect((host, int(port)))

    d = Dashboard(host, int(port))
    
    # message loop
    while(True):
        d.select_photo()
        user = d.select_user()
        print(user)
        
        #clientfd.sendall(data)

    clientfd.close()

if __name__ == "__main__":
    main()
