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
import datetime
from backenddashboard import BackendDashboard

clients = {}  # store the connfd
logged_in = {} # Keeps track of the users who logged in
admin_logged_in = {} # admin/superadmin log in tracker


# Initialize logging
log_file = open("server.log", "a")

def log_action(connfd, username, role, action, status):
    IP_address = connfd.getpeername()

    # Get the current date and time
    current_datetime = datetime.datetime.now()

    # Define the desired format
    desired_format = "%d/%b/%Y:%H:%M:%S %z"
    formatted_timestamp = current_datetime.strftime(desired_format)


    log_entry = "Time: " + formatted_timestamp + ", IP address: " + str(IP_address[0])+ ", Username: " + username + ", Status: " + status + ", Action: " + action + ", Role: " + role + "\n"
    log_file.write(log_entry)
    log_file.flush()  # Flush the buffer to ensure the log entry is written immediately

# session_manager = SessionManager()
generate = Generate()
backenddashboard = BackendDashboard()

def user_handler(connfd, username):
    try:
        while True:
            # action = connfd.recv(1024).decode()
            
            data = connfd.recv(1024)

            # Decode data from bytes to string
            data_str = data.decode('utf-8')

            # Parse JSON data
            auth_info = json.loads(data_str)

            # Extract username and password
            user = auth_info['username']
            action = auth_info['password']
            print(user)
            print(action)
            
            if user == None and action == "END_SESSION":
                print("Session ended by the client.")
                break

            if user == None and action == "send":
                # Convert the dictionary to a JSON string
                logged_in_json = json.dumps(logged_in)

                # Encode the JSON string to bytes
                logged_in_bytes = logged_in_json.encode('utf-8')
                
                #send list of available users
                connfd.sendall(logged_in_bytes)
                continue
            
            if (user in clients) and action == "send":
                print("in here")
                recipient = user
                #print(recipient)
                #print(logged_in)
                if logged_in[recipient] == 'yes':
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
                    print("file sent successfully")
                
            elif user != None and action == "Delete":
                if backenddashboard.delete_self(user):
                    connfd.sendall("User Removed".encode())
                    break
                
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        print(f'{username} logged out')
        try:
            log_action(connfd, username, "User", "Log Out", "Success")
            connfd.close()
            del clients[username]
            del logged_in[username]
            print("SSL socket closed successfully")
        except Exception as e:
            print("Error closing SSL socket:", e)
            import traceback
            traceback.print_exc()
        
def create_user_helper(connfd, username):
        
    if backenddashboard.check_user_taken(username):
        connfd.sendall("Username taken".encode())
        return
        # send a message back to user that username is taken
    else:
        connfd.sendall("Valid".encode())
        data = connfd.recv(1024)

        # Decode data from bytes to string
        data_str = data.decode('utf-8')

        # Parse JSON data
        auth_info = json.loads(data_str)

        # Extract username and password
        username = auth_info['username']
        password = auth_info['password']
        
        return (username, password)

def client_handler(connfd):
    try:
        while True:
            # Receive the login username and password from the client
            data = connfd.recv(1024)
            
            # Decode data from bytes to string
            data_str = data.decode('utf-8')

            if data_str == 'QUIT_AUTH_FAILED':
                print(f'{username} logged out')
                try:
                    connfd.close()
                    print("SSL socket closed successfully")
                    break
                except Exception as e:
                    print("Error closing SSL socket:", e)
                    import traceback
                    traceback.print_exc()
            elif data_str == 'CONTINUE':
                continue
            
            # Parse JSON data
            auth_info = json.loads(data_str)

            # Extract username and password
            username = auth_info['username']
            password = auth_info['password']
            print(username, password)
            
            if password == "Create User":
                if backenddashboard.check_user_taken(username):
                    connfd.sendall("Username taken".encode())
                    continue
                    # send a message back to user that username is taken
                else:
                    connfd.sendall("Valid".encode())
                    data = connfd.recv(1024)
            
                    # Decode data from bytes to string
                    data_str = data.decode('utf-8')

                    # Parse JSON data
                    auth_info = json.loads(data_str)

                    # Extract username and password
                    username = auth_info['username']
                    password = auth_info['password']
                    
                    backenddashboard.create_user(2, username, password)
                    log_action(connfd, username, "User", "Create Account", "Success")
                    # username is valid now prompt for password
            else:
                # authentication check
                print("goes into auth")
                auth = backenddashboard.auth_login(username, password)
                print(auth)
                
                if auth == "0":
                    print(f"Superadmin {username} authenticated successfully.")
                    clients[username] = connfd
                    admin_logged_in[username] = 'yes'
                    log_action(connfd, username, "Superadmin", "Log In", "Success")
                    print(f"{username} logged in.")
                    
                    connfd.sendall(str(auth).encode())
                    
                    try:
                        while True:
                            data = connfd.recv(1024)
            
                            # Decode data from bytes to string
                            data_str = data.decode('utf-8')

                            # Parse JSON data
                            auth_info = json.loads(data_str)

                            # Extract username and password
                            username = auth_info['username']
                            action = auth_info['password']
                            
                            if action == "Create User":
                                username, password = create_user_helper(connfd, username)
                                if username:
                                    backenddashboard.create_user(2, username, password)
                                    log_action(connfd, username, "Superadmin", "Create Account", "Success")
                                else:
                                    continue
                                
                            elif action == "Create Admin":
                                username, password = create_user_helper(connfd, username)
                                if username:
                                    backenddashboard.create_user(1, username, password)
                                    log_action(connfd, username, "Superadmin", "Create Admin", "Success")
                                else:
                                    continue

                            elif action == "Delete":
                                target_user = auth_info['target_user']
                                status = backenddashboard.delete_user(username, target_user)
                                if status == 0:
                                    connfd.sendall("Denied".encode())
                                elif status == 1:
                                    log_action(connfd, username, "Superadmin", "Delete Account", "Success")
                                    connfd.sendall("Success".encode())
                                    # if (target_user in logged_in) or (target_user in admin_logged_in):
                                    #     if target_user in clients:
                                    #         clients[target_user].sendall()
                                    #     break
                                elif status == 2:
                                    connfd.sendall("User not found".encode())
                            
                            elif action == "Logs":
                                print("ABOUT TO SEND")
                                with open('server.log', 'rb') as log_file:
                                    while True:
                                        data = log_file.read(1024)  # Read in chunks of 1KB
                                        print(data)
                                        if not data:
                                            break  # If no more data, stop the loop
                                        connfd.sendall(data)
                                    connfd.sendall(b"END_OF_FILE")

                            elif action == "END_SESSION_SUPER_ADMIN":
                                    break
                    
                    except Exception as e:
                        print(f"An error occurred: {e}")
                                 
                    finally:
                        print(f'{username} logged out')
                        try:
                            log_action(connfd, username, "Superadmin", "Log Out", "Success")
                            connfd.close()
                            del clients[username]
                            del admin_logged_in[username]
                            print("SSL socket closed successfully")
                            break
                        except Exception as e:
                            print("Error closing SSL socket:", e)
                            import traceback
                            traceback.print_exc()
                    
                  
                elif auth == "1":
                    print(f"admin {username} authenticated successfully.")
                    clients[username] = connfd
                    admin_logged_in[username] = 'yes'
                    log_action(connfd, username, "Admin", "Log In", "Success")
                    print(f"{username} logged in.")
                    
                    connfd.sendall(str(auth).encode()) 
                    
                    try:
                        while True:
                            data = connfd.recv(1024)
            
                            # Decode data from bytes to string
                            data_str = data.decode('utf-8')

                            # Parse JSON data
                            auth_info = json.loads(data_str)

                            # Extract username and password
                            username = auth_info['username']
                            action = auth_info['password']
                            
                            if action == "Create User":
                                username, password = create_user_helper(connfd, username)
                                if username:
                                    backenddashboard.create_user(2, username, password)
                                    log_action(connfd, username, "Admin", "Create User", "Success")
                                else:
                                    continue
                                
                            elif action == "Create Admin":
                                username, password = create_user_helper(connfd, username)
                                if username:
                                    backenddashboard.create_user(1, username, password)
                                    log_action(connfd, username, "Admin", "Create Admin", "Success")
                                else:
                                    continue

                            elif action == "Delete":
                                target_user = auth_info['target_user']
                                status = backenddashboard.delete_user(username, target_user)
                                print(status)
                                if status == 0:
                                    connfd.sendall("Denied".encode())
                                elif status == 1:
                                    log_action(connfd, username, "Admin", "Delete Account", "Success")
                                    connfd.sendall("Success".encode())
                                    # if they are logged in they are logged out
                                elif status == 2:
                                    connfd.sendall("User not found".encode())
                            
                            elif action == "END_SESSION_ADMIN":
                                break
                                
                    except Exception as e:
                        print(f"An error occurred: {e}")
                                 
                    finally:
                        print(f'{username} logged out')
                        try:
                            log_action(connfd, username, "Admin", "Log Out", "Success")
                            connfd.close()
                            del clients[username]
                            del admin_logged_in[username]
                            print("SSL socket closed successfully")
                            break
                        except Exception as e:
                            print("Error closing SSL socket:", e)
                            import traceback
                            traceback.print_exc()
                    
                    
                elif auth == "2":
                    print(f"{username} authenticated successfully.")
                    connfd.sendall(str(auth).encode()) 
                    clients[username] = connfd
                    logged_in[username] = 'yes'
                    print(f"{username} logged in.")
                    log_action(connfd, username, "User", "Log In", "Success")
                    user_handler(connfd, username)
                    break
                    
                elif auth == "User does not exist":
                    connfd.sendall(str(auth).encode())
                    break
                    
                else:
                    failed_role = auth[1]
                    if failed_role == "0":
                        failed_role = "Superadmin"
                    elif failed_role == "1":
                        failed_role = "Admin"
                    elif failed_role == "2":
                        failed_role = "User"
                    print(f"Authentication failed for user {username}.")
                    log_action(connfd, username, failed_role, "Log In", "Failed")
                    connfd.sendall("Login failed.".encode())
                    break
            

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


