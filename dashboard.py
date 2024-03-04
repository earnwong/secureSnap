from easygui import *
import sys
import socket
import hashlib

dummy_users = {
    "bob": hashlib.sha256("password1".encode()).hexdigest(),
    "samantha": hashlib.sha256("password2".encode()).hexdigest(),
}

class Dashboard: 
    def __init__(self, host, port):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((host, port))

    def select_photo(self):
        file_path = fileopenbox(msg="Select a file to send", title="Select File")

        if file_path:
            with open(file_path, 'rb') as file:
                while True:
                    chunk = file.read(1024)  # Read the file in chunks of 1024 bytes
                    if not chunk:
                        break  # If no more data, stop the loop
                    self.client_socket.sendall(chunk)  # Send the chunk immediately

                print("File sent successfully.")
        else:
            print("No file selected.")

    def select_user(self):
        username_list = list(dummy_users.keys())  # Extract the usernames from the dummy_users dictionary
        selected_user = choicebox(msg="Select a User", title="User Selection", choices=username_list)
        return selected_user
        
        # if file_path:
        #     with open(file_path, 'rb') as file:
        #         chunk = file.read(1024)

        #         data = file.read()
        #         print("File sent successfully.")
        # else:
        #     print("No file selected.")

        # return chunk

    # def recieve_and_open(self):
    #     with open('received.jpg', 'wb') as file:
    #         while True:
    #             data = self.client_socket.recv(1024)  # Receive data in chunks
    #             if not data:
    #                 break  # No more data to receive
    #             file.write(data)  # Write the received data to a file

    #         print("File received!")

        # with open('received.jpg', 'wb') as file:
        #     file.write(data)x
        #     print("File received!")
    def close_connection(self):
        self.client_socket.close()
        

    # def select_user():
