
import sys
import socket
import hashlib
import easygui
import select
# from frontenddashboard2 import FrontendDashboard


class Dashboard: 
    def __init__(self, client_socket):
        self.client_socket = client_socket        
        
    def select_photo(self, recipient):
        #print("I reach select photo")

        file_path = easygui.fileopenbox(msg="Select a file to send", title="Select File")


        if file_path:
            with open(file_path, 'rb') as file:
                while True:
                    chunk = file.read(1024)  # Read the file in chunks of 1024 bytes
                    
                    if not chunk:
                        break  # If no more data, stop the loop
                    
                    
                    self.client_socket.sendall(chunk)  # Send the chunk immediately
                print("File sent successfully.")
                easygui.msgbox(f'Photo sent to {recipient}', title="User Selection")
        else:
            print("No file selected.")

    
    def receive_photo1(self, server_socket, username):
        sockets_to_read = [server_socket]

        # List of sockets to monitor for write readiness (if needed)
        sockets_to_write = []

        # List of sockets to monitor for errors (if needed)
        sockets_with_errors = []

        # Timeout in seconds
        timeout = 1  # Example timeout value, adjust as needed

        # Use select to check for read readiness
        readable, writable, exceptional = select.select(sockets_to_read, sockets_to_write, sockets_with_errors, timeout)
        if not readable:
            #print("no files to receive")
            return False
        else:
            with open(f'client/output/{username}_output.jpg', 'wb') as file:
                while True:       
                    data = server_socket.recv(1024)  # Receive data in chunks
                    if data.endswith(b"END_OF_FILE"):
                    # Remove the END_OF_FILE bytes before saving
                        file.write(data[:-len(b"END_OF_FILE")])
                        #print("Photo received successfully.")
                        break
                    file.write(data)

        return True

    def close_connection(self):
        self.client_socket.close()
        
        

