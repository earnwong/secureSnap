import sys
import socket
from os import _exit as quit
import threading
from encrypt import Generate
import base64
from Crypto.Cipher import PKCS1_OAEP
import json
import threading
import ssl
from backenddashboard import BackendDashboard

clients = {}  # store the connfd
logged_in = {} # Keeps track of who logged in
admin_logged_in = {} # admin log in tracker

# session_manager = SessionManager()
generate = Generate()
backenddashboard = BackendDashboard()

def user_handler(connfd, username):
    try:
        while True:
            recipient = connfd.recv(1024).decode()
            if recipient == "END_SESSION":
                print("Session ended by the client.")
                break

            if recipient == "send":
                # Convert the dictionary to a JSON string
                logged_in_json = json.dumps(logged_in)

                # Encode the JSON string to bytes
                logged_in_bytes = logged_in_json.encode('utf-8')
                
                #send list of available users
                connfd.sendall(logged_in_bytes)
                continue
                
            if (recipient in clients) and logged_in[recipient] == 'yes':
                connfd.sendall("This user is available".encode('utf-8'))
                
                while True:
                    data = connfd.recv(1024) 
                    
                    if (len(data) < 1024):
                        clients[recipient].sendall(data)
                        print("no more data")
                        sys.stdout.flush()
                        break  # No more data to receive
                    clients[recipient].sendall(data)
                    
                clients[recipient].sendall(b"END_OF_FILE")
        
                
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        print(f'{username} logged out')
        connfd.close()
        del clients[username]
        del logged_in[username]

def client_handler(connfd):
    try:
        # Receive the login username and password from the client
        data = connfd.recv(1024)
        
        # Decode data from bytes to string
        data_str = data.decode('utf-8')

        # Parse JSON data
        auth_info = json.loads(data_str)

        # Extract username and password
        username = auth_info['username']
        password = auth_info['password']
        
        print(username, password)

        # Authentication process
        auth = backenddashboard.auth_login(username, password)
        print(auth)
            
        if auth == "0":
            print(f"Superadmin {username} authenticated successfully.")
            connfd.sendall(str(auth).encode()) 
            
        elif auth == "1":
            print(f"admin {username} authenticated successfully.")
            connfd.sendall(str(auth).encode()) 
            
        elif auth == "2":
            print(f"{username} authenticated successfully.")
            connfd.sendall(str(auth).encode()) 
            clients[username] = connfd
            logged_in[username] = 'yes'
            print(f"{username} logged in.")
            
            user_handler(connfd, username)

        elif auth == "User does not exist":
            connfd.sendall(str(auth).encode()) 
            
        else:
            print(f"Authentication failed for user {username}.")
            connfd.sendall("Login failed.".encode())
            

    except json.JSONDecodeError:
        print("Failed to decode JSON data")
        connfd.sendall("Invalid data format.".encode())
    except KeyError:
        print("Username or password missing")
        connfd.sendall("Missing credentials.".encode())
    except Exception as e:
        print(f"An error occurred: {e}")
        connfd.sendall("Error processing your request.".encode())
        print("here 1")
        

        
def main():
    # parse arguments
    if len(sys.argv) != 2:
        print("usage: python3 %s <port>" % sys.argv[0])
        quit(1)
    port = sys.argv[1]
    # config = sys.argv[2]
    
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain('certificate.pem', 'private_key.pem')
    
    listenfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listenfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listenfd.bind(('', int(port)))
    listenfd.listen(5)
    secure_listenfd = context.wrap_socket(listenfd, server_side=True)
    
    while True:
        connfd, addr = secure_listenfd.accept()
        thread = threading.Thread(target=client_handler, args=(connfd,))
        thread.start()
    
    # close connection
    connfd.close()
    listenfd.close()


if __name__ == "__main__":
    main()


