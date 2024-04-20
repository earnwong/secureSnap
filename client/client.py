import sys
import socket
from os import _exit 
from dashboard import Dashboard
# from server.encrypt import EncryptDecrypt
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import json
from frontenddashboard2 import FrontendDashboard
import time
import threading
import select
import ssl
import easygui


frontend_dashboard = FrontendDashboard()
lock = threading.Lock()
pause_event = threading.Event()
role = None


def connect_to_server(host, port):
    try: 
        # Create a standard socket
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Define the context for SSL
        context = ssl.create_default_context()
        context.check_hostname = False
        context.load_verify_locations('server/certificate.pem')  # Load the trusted server certificate

        # Wrap the socket with SSL
        secure_socket = context.wrap_socket(raw_socket, server_hostname=host)

        # Connect to the server
        secure_socket.connect((host, port))

        return secure_socket
    
    except ssl.SSLError as e:
        print(f"SSL error: {e}")
    except Exception as e:
        print(f"Failed to connect: {e}")
        

def receive_photos_continuously(server_socket, username):
    d = Dashboard(server_socket)
    while True:
        if pause_event.is_set():
                continue
        try:

            d.receive_photo1(server_socket, username)
            time.sleep(2)  # Wait for 2 seconds before the next check
        except Exception as e:
            print(f"Error while receiving photos: {e}")
            break
        
        
def user_handler(server_socket, username, d): 
    while True:
        action = frontend_dashboard.user_menu(username)

        if action == "send":
            pause_event.set()
            
            try:
                server_socket.sendall(action.encode())
                
                logged_in = server_socket.recv(1024)
                
                # Decode the bytes back to a string
                data_str = logged_in.decode('utf-8')
                
                # Convert the JSON string back to a dictionary
                logged_in_received = json.loads(data_str)
                print(username)
                print(logged_in_received)
                
                recipient = frontend_dashboard.select_user(logged_in_received, username)

                if recipient:
                    server_socket.sendall(recipient.encode())
                    response = server_socket.recv(22).decode('utf-8')
                
                    if response == "This user is available":
                        frontend_dashboard.display_message("This user is available")
                        
                        d.select_photo(recipient)
                        
                    else:
                        print(response)
            finally:
                pause_event.clear()

        elif action == "end":
            pause_event.set()
            server_socket.sendall("END_SESSION".encode())
            sys.exit(0) # Exits the program
        else:
            pause_event.set()
            print("Invalid action. Please try again.")
            
        
        
def main():
    # parse arguments
    if len(sys.argv) != 3:
        print("usage: python3 %s <host> <port>" % sys.argv[0]);
        quit(1)
    host = sys.argv[1]
    port = sys.argv[2]

    while True:
        # Connect to the server
        server_socket = connect_to_server(host, int(port))
        
        if not server_socket:
            print("Failed to connect to the server.")
            continue
        else:
            # Prompt user for username and password
            username, password = frontend_dashboard.login()
            print(username, password)
            
            if username == "Create user": # no functionality yet
                server_socket.sendall("Create user".encode())
            else:
                # Send the username and password after connecting
                login_info = {'username': username, 'password': password}
                server_socket.sendall(json.dumps(login_info).encode())

        # Wait for response from the server regarding the login attempt
        response = server_socket.recv(1024).decode()

        if response == "0" or response == "1" or response == "2":
            print("Logged in successfully.")
            role = response
            break  # Exit the loop if login is successful
        
        elif response == "Login failed.":
            # Handle login failure
            quitbox = easygui.buttonbox("Incorrect password. Quit?", choices=["Quit", "Continue"])
            if quitbox == "Quit":
                server_socket.sendall("END_SESSION".encode())
                server_socket.close()
                _exit(0)  # Exits the program
            else:
                # Close the current connection and loop to retry login
                server_socket.sendall("END_SESSION".encode())
                server_socket.close()
        elif response == "User does not exist":
            frontend_dashboard.display_message("This user does not exist.")
        
        else:
            print("Unexpected response from server:", response)
            server_socket.close()
        
    
    if role == "0":
        frontend_dashboard.superadmin_menu(username)
    
    if role == "1":
        frontend_dashboard.admin_menu(username)
        
    if role == "2":
        d = Dashboard(server_socket)
    
        photo_thread = threading.Thread(target=receive_photos_continuously, args=(server_socket, username))
        photo_thread.start()
        
        try:
            user_handler(server_socket, username, d)
                            
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            print("server socket closed")
            server_socket.close()
            

if __name__ == "__main__":
    main()
