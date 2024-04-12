import sys
import socket
from os import _exit as quit
from dashboard import Dashboard
from encrypt import EncryptDecrypt
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import json
from frontenddashboard import FrontendDashboard
import time
import threading


frontend_dashboard = FrontendDashboard()

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

def receive_photos_continuously(server_socket, username, d):
    while True:
        try:
            # Assuming the server sends a specific flag or message when a photo is available
            data = server_socket.recv(1024).decode()
            print(data)
            if data == "photo_available":
                rec = d.receive_photo1(server_socket, username)
                if rec:
                    frontend_dashboard.display_message("File received successfully")
                else:
                    frontend_dashboard.display_message("No files to receive")
            time.sleep(1)  # Wait for 2 seconds before the next check
        except Exception as e:
            print(f"Error while receiving photos: {e}")
            break


def main():
    # parse arguments
    if len(sys.argv) != 3:
        print("usage: python3 %s <host> <port>" % sys.argv[0]);
        quit(1)
    host = sys.argv[1]
    port = sys.argv[2]

    username = frontend_dashboard.login()
    
    server_socket = connect_to_server(host, int(port), username)
    response = server_socket.recv(1024).decode()
    print(response)
    
    d = Dashboard(server_socket)
    encdec = EncryptDecrypt()
    
    ## CHANGE THIS IT DOESNT GENERATE EVERYTIME 
    encdec.generate_rsa_keys(username)
    
    photo_thread = threading.Thread(target=receive_photos_continuously, args=(server_socket, username, d))
    photo_thread.start()
    
    try:
        while True:
            action = frontend_dashboard.menu(username)
            print(action)

            # if action == "continue":
            #     rec = d.receive_photo1(server_socket, username)
            #     if rec:
            #         frontend_dashboard.display_message("File received successfully")
            #     else: 
            #         frontend_dashboard.display_message("No files to receive")

            if action == "send":
                server_socket.sendall(action.encode())
                logged_in = server_socket.recv(1024)
                # Decode the bytes back to a string
                data_str = logged_in.decode('utf-8')

                # Convert the JSON string back to a dictionary
                logged_in_received = json.loads(data_str)
                
                recipient = frontend_dashboard.select_user(logged_in_received, username)
                if recipient:

                    server_socket.sendall(recipient.encode())
                    response = server_socket.recv(1024).decode()
                
                    if response == "This user is available":
                        frontend_dashboard.display_message("This user is available")
                        aes_key = server_socket.recv(1024)
                        
                        priv_key = encdec.load_rsa_private_key(username)
                        aes_key = decrypt_aes_key(priv_key, aes_key)
                        
                        d.select_photo(aes_key, recipient)
                        frontend_dashboard.display_message(f'Photo sent to {recipient}')
                    else:
                        print(response)

            elif action == "end":
                server_socket.sendall("END_SESSION".encode())
                quit()  # Exits the program
            else:
                print("Invalid action. Please try again.")
 
                        
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        server_socket.close()
            

if __name__ == "__main__":
    main()
