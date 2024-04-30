
import socket
import hashlib
import easygui
import select
import os
import imghdr
# from frontenddashboard2 import FrontendDashboard


class Dashboard: 
    def __init__(self, client_socket):
        self.client_socket = client_socket        
        
    def select_photo(self):
        def format_size(size_in_bytes):
            # Convert bytes to megabytes
            size_in_mb = size_in_bytes / (1024 * 1024)
            if size_in_mb < 1024:
                return f"{size_in_mb:.2f} MB"
            else:
                # Convert megabytes to gigabytes
                size_in_gb = size_in_mb / 1024
                return f"{size_in_gb:.2f} GB"
            
        while True:
            file_path = easygui.fileopenbox(msg="Select a file to send", title="Select File")

            if file_path:
                # Check the file format using imghdr
                file_format = imghdr.what(file_path)
                if file_format not in ['png', 'jpeg', 'jpg']:
                    easygui.msgbox("Selected file is not a PNG, JPEG or JPG.")
                    continue

                # Check file size
                file_size = os.path.getsize(file_path)
                max_size = 2.5 * 1024 * 1024  # 2.5 MB limit
                if file_size > max_size:
                    formatted_file_size = format_size(file_size)
                    easygui.msgbox(f"File is too large ({formatted_file_size} bytes). Maximum allowed size is 2.5 MB.")
                    continue

                return file_path
            else:
                print("No file selected.")
                return None

       

    def send_photo(self, file_path, recipient):
        #print("I reach select photo")


        if file_path:
            #print("I end up going here")
            #print(file_path)
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
            print("no files to receive")
            return False
        else:
            print("there is a file to be received")
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
        
        

