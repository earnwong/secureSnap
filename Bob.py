import sys
import socket
from os import _exit as quit
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
from dashboard import Dashboard

        
def main():
    # parse arguments
    if len(sys.argv) != 2:
        print("usage: python3 %s <port>" % sys.argv[0])
        quit(1)
    port = sys.argv[1]
    # config = sys.argv[2]
    
    # open a socket
    listenfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listenfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # bind socket to ip and port
    listenfd.bind(('', int(port)))

    # listen to socket
    listenfd.listen(1)

    # accept connection
    (connfd, addr) = listenfd.accept()


    # message loop
    while(True):
        with open('received.jpg', 'wb') as file:
            while True:
                data = connfd.recv(1024)  # Receive data in chunks
                if not data:
                    break  # No more data to receive
                file.write(data)  # Write the received data to a file

            print("File received!")


        # print("Received from Alice: %s" % msg)
        # if config == "ENC":
        #     delimiter = b'<<DELIMITER>>'
        #     received_parts = msg.split(delimiter)
        #     encrypted_message = received_parts[0]
        #     encrypted_aes_key = received_parts[1]
        #     iv = received_parts[2]
        #     decrypted_msg = aes_decrypt(encrypted_message, encrypted_aes_key, iv)
            
        #     print("Received from Alice: %s" % decrypted_msg)
           
        # elif config == "MAC":
        #     delimiter = b'<<DELIMITER>>'
        #     received_parts = msg.split(delimiter)
        #     message = received_parts[0].decode('utf-8')
        #     mac = received_parts[1]
            
        #     if hmac_verify(message, mac):
        #         print("Message from Alice: ", message)

        # elif config == "ENCMAC":
        #     delimiter = b'<<DELIMITER>>'
        #     received_parts = msg.split(delimiter)
        #     #print("Received parts:", received_parts)
        #     mac = received_parts[0]
        #     enc_msg = received_parts[1]
        #     enc_aes_key = received_parts[2]
        #     iv = received_parts[3]
        #     enc_then_mac_Bob(mac, enc_msg, enc_aes_key, iv)

        # else:
        

    # close connection
    connfd.close()
    listenfd.close()


if __name__ == "__main__":
    main()





# def hmac_verify(msg, mac, enc=False):
#     with open("h_key.bin", "rb") as h:
#         h_key = h.read()
#     ver_key = HMAC.new(h_key, digestmod=SHA256)
#     if enc: 
#         ver_key.update(msg)
#     else:
#         ver_key.update(msg.encode('utf-8'))
#     try:
#         ver_key.verify(mac)
#         print(f"HMAC verified successfully.")
#         return 1
#     except ValueError:
#         print(f"Failed to verify HMAC! Your message has been tampered with.")
#         return 0
    

# def aes_decrypt(enc_msg, enc_aes_key, iv):
#     b_private_key = RSA.import_key(open("b_private_key.pem").read())
#     a_public_key = RSA.import_key(open("a_public_key.pem").read())
#     b_public_key = RSA.import_key(open("b_public_key.pem").read())
    
#     cipher_rsa = PKCS1_OAEP.new(b_private_key)
#     decrypted_aes_key = cipher_rsa.decrypt(enc_aes_key)
    
#     # Create a new AES cipher in CTR mode using the decrypted AES key and the nonce
#     cipher_aes = AES.new(decrypted_aes_key, AES.MODE_CTR, nonce=iv)
    
#     # Decrypt the message
#     aes_dec = cipher_aes.decrypt(enc_msg)
        
#     return aes_dec.decode('utf-8')

# def enc_then_mac_Bob(mac, enc_msg, enc_aes_key, iv):
#     if hmac_verify(enc_msg, mac, enc=True):
#         print("Message from Alice: ", aes_decrypt(enc_msg, enc_aes_key, iv))