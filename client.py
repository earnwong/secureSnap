import sys
import socket
from os import _exit as quit
import easygui
from dashboard import Dashboard
from encrypt import EncryptDecrypt
import base64
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


def decrypt_aes_key(client_private_rsa_key, encrypted_aes_key):
    # Decrypt the AES key using the client's private RSA key
    cipher_rsa = PKCS1_OAEP.new(client_private_rsa_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    # Return the decrypted AES key
    return aes_key

def connect_to_server(host, port, username):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((host, port))
    server_socket.sendall(username.encode())  # Send the username right after connecting
    return server_socket

def main():
    # parse arguments
    if len(sys.argv) != 3:
        print("usage: python3 %s <host> <port>" % sys.argv[0]);
        quit(1)
    host = sys.argv[1]
    port = sys.argv[2]

    username = input("Enter your username: ")
    server_socket = connect_to_server(host, int(port), username)
    response = server_socket.recv(1024).decode()
    print(response)

    if response == "Wrong username":
        print("Login failed. Please check your username.")
        server_socket.close()
        return
    
    d = Dashboard(server_socket)
    encdec = EncryptDecrypt()
    
    ## CHANGE THIS IT DOESNT GENERATE EVERYTIME 
    encdec.generate_rsa_keys(username)
    
    try:
        while(True):
            print("Would you like to send a photo, end session, or continue? Enter 'send', 'end', or 'continue':")
            #print("Would you like to send a photo or end session? Enter 'send' or 'end':")
            action = input().lower()
            
            
            if action == "continue":
                d.receive_photo1(server_socket, username)
                continue
            elif action == "send":
                recipient = input("Who would you like to send it to?: ")
                server_socket.sendall(recipient.encode())
                response = server_socket.recv(1024).decode()
            
                if response == "This user is available":
                    print(response)
                    aes_key = server_socket.recv(1024)
                    
                    priv_key = encdec.load_rsa_private_key(username)
                    aes_key = decrypt_aes_key(priv_key, aes_key)
                    
                    d.select_photo(aes_key, recipient)
                    #d.receive_photo(server_socket)
                    continue
                else:
                    print(response)

            elif action == 'end':
                server_socket.sendall("END_SESSION".encode())
                break
            else:
                print("Invalid option, please try again.")
                        
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        server_socket.close()
            

if __name__ == "__main__":
    main()
