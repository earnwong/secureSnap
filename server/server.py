import sys
import socket
from os import _exit as quit
import threading
import json
import threading
import ssl
import datetime
from backenddashboard import BackendDashboard


clients = {}  # store the connfd
logged_in = {} # Keeps track of the users who logged in
admin_logged_in = {} # admin/superadmin log in tracker
blocked_users = {} # stores blocked users
alerts = {} # stores failed attempts

backenddashboard = BackendDashboard() # for backend functionality

# Initialize logging
log_file = open("server.log", "a")

# Initialize logging for alert-specific entries
alert_log_file = open("alerts.log", "a")

def log_action(connfd, username, action_user, role, action, status):
    """
    Logs actions taken by users along with their authentication status, the action taken,
    and relevant user and system information.

    Args:
        connfd (socket): The socket connection file descriptor through which the user is connected.
        username (str): The username of the user who is subject to the action.
        action_user (str): The username of the user who performed the action.
        role (str): The role of the user who performed the action (e.g., 'Admin', 'User').
        action (str): The specific action being logged (e.g., 'Log In', 'Delete Account').
        status (str): The result of the action (e.g., 'Success', 'Failed').

    Side effects:
        Writes a log entry to a log file. This includes the current timestamp, the user's IP address,
        the action taken, and the outcome of the action.
        Monitors for multiple failed login attempts and logs security alerts if necessary.
    """
    
    IP_address = connfd.getpeername()

    # Get the current date and time
    current_datetime = datetime.datetime.now()

    # Define the desired format
    desired_format = "%d/%b/%Y:%H:%M:%S %z"
    formatted_timestamp = current_datetime.strftime(desired_format)


    log_entry = "Time: " + formatted_timestamp + ", IP address: " + str(IP_address[0])+ ", Username: " + username + ", Status: " + status + ", Action: " + action + ", Done By: " + action_user + ", Role: " + role + "\n"
    log_file.write(log_entry)
    log_file.flush()  # Flush the buffer to ensure the log entry is written immediately
    
    # Check if the action is a login attempt and it failed
    if action == "Log In" and status == "Failed":
        key = (username, str(IP_address[0]))
        if key not in alerts:
            alerts[key] = {'count': 1, 'first_attempt_time': current_datetime}
        else:
            alerts[key]['count'] += 1

        
        # Check if there are three failed attempts within 5 minutes
        if alerts[key]['count'] == 3:
            time_difference = (current_datetime - alerts[key]['first_attempt_time']).total_seconds()
            print(time_difference)
            if time_difference <= 300:  # 300 seconds is 5 minutes
                # Log the alert to the alert log file
                alert_message = f"ALERT: {formatted_timestamp} : Three failed login attempts for user {username} from IP {IP_address} within 5 minutes.\n"
                alert_log_file.write(alert_message)
                alert_log_file.flush()
                print(alert_message)

            # Reset the count after logging the alert or if the attempts are spread over more than 5 minutes
            alerts[key] = {'count': 0, 'first_attempt_time': current_datetime}




def user_handler(connfd, username):
    """
    Handles interactions with a user after they've logged in, managing various user actions
    like sending data, blocking users, and deleting their account.

    Args:
        connfd (socket): The socket connection file descriptor for communication with the user.
        username (str): The username of the user who is interacting with the system.

    Side effects:
        Processes various commands sent by the user and interacts with the backend to carry out
        these commands. Logs out the user and closes the socket connection when the session ends.
    """
    try:
        while True:
            
            data = connfd.recv(1024)

            data_str = data.decode('utf-8')

            auth_info = json.loads(data_str)

            # Extract username and password
            user = auth_info['username']
            action = auth_info['password']
 
            if user == None and action == "END_SESSION":
                print("Session ended by the client.")
                break

            elif user == None and action == "send":
                # Convert the dictionary to a JSON string
                logged_in_json = json.dumps(logged_in)

                # Encode the JSON string to bytes
                logged_in_bytes = logged_in_json.encode('utf-8')
                
                #send list of available users
                connfd.sendall(logged_in_bytes)
                continue
            
            elif (user in clients) and action == "send":
                recipient = user
                if logged_in[recipient] == 'yes':
                    if username not in blocked_users[recipient]:
                        connfd.sendall("This user is available".encode('utf-8'))
                        
                        check_cancel_send = connfd.recv(1024).decode()
                        if check_cancel_send == "Cancel send":
                            continue
                        elif check_cancel_send == "Sending":
                            while True:
                                data = connfd.recv(1024) 
                                
                                if (len(data) < 1024):
                                    clients[recipient].sendall(data)
                                    sys.stdout.flush()
                                    break  # No more data to receive
                                clients[recipient].sendall(data)
                                
                            clients[recipient].sendall(b"END_OF_FILE")
                            print("file sent successfully")
                        
                    else:
                        connfd.sendall("Blocked".encode('utf-8'))
                        continue
                    
                    
            
            elif (user == None) and action == "block":
                continue

            elif (user != None) and action == "block": 
                user_to_block = connfd.recv(1024).decode()
                user_to_block = str(user_to_block)
                status = backenddashboard.check_blocked_user(user, user_to_block)
                if status == 1:
                    blocked_users[user].extend([user_to_block])
                connfd.sendall(str(status).encode())
                continue

            elif user != None and action == "Delete":
                if backenddashboard.delete_self(user):
                    log_action(connfd, user, user, "User", "Delete Account", "Success")
                    connfd.sendall("User Removed".encode())
                    break

                
                
    except json.JSONDecodeError:
        print("Failed to decode JSON data")
        connfd.sendall("Invalid data format.".encode())
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        print(f'{username} logged out')
        try:
            log_action(connfd, username, username, "User", "Log Out", "Success")
            connfd.close()
            del clients[username]
            del logged_in[username]
            print("SSL socket closed successfully")
        except Exception as e:
            print("Error closing SSL socket:", e)
            import traceback
            traceback.print_exc()
        
def create_user_helper(connfd, username):
    """
    Assists in the creation of a new user, handling preliminary checks for username availability and
    email validation.

    Args:
        connfd (socket): The socket connection file descriptor for sending responses back to the client.
        username (str): The username (or email) proposed for the new user account.

    Returns:
        tuple: Returns a tuple of (username, password) if valid, otherwise (None, None).

    Side effects:
        Sends messages back to the client indicating the status of the username (taken or available)
        and email validation.
    """
    
    if backenddashboard.check_user_taken(username):
        # send a message back to user that username is taken
        connfd.sendall("Username taken".encode())
        return (None, None)
    
    elif not backenddashboard.is_valid_email(username):
        connfd.sendall("Email not valid".encode())
        return (None, None)
    
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

def verify_pin_helper(connfd, email):
    """
    Helps verify the PIN sent to a user's email during processes like password reset or account verification.

    Args:
        connfd (socket): The socket connection for communication.
        email (str): The email address of the user attempting verification.

    Returns:
        bool: True if the PIN is verified successfully, False otherwise.

    Side effects:
        Handles the interaction with the user for PIN verification and sends further instructions
        based on the outcome of the verification.
    """
    
    # generate pin and send
    pin = backenddashboard.send_email_and_return_pin(email)
    # verify pin
    connfd.sendall("Get PIN".encode())
    while True:  

        pin_to_verify = connfd.recv(1024).decode() 
        
        pin_verified = backenddashboard.verify_pin(pin_to_verify,pin)

        if pin_verified:
            # request new pw
            connfd.sendall("Get new password".encode())
            
            new_password = connfd.recv(1024).decode()
            
            if new_password == "Cancel":
                return False

            else:       
                role = backenddashboard.get_auth_level(email)
                backenddashboard.update_pw(email, new_password, role)
                
                str_role = backenddashboard.get_auth_level_str(role)
                
                log_action(connfd, email, email, str_role, "Reset Password", "Success")
                connfd.sendall("Password updated".encode())
                return True
        
        else:
            connfd.sendall("PIN not verified".encode())
            return False


def client_handler(connfd):
    """
    Handles client connections and manages the session lifecycle, including login attempts,
    user creation, and password reset actions.

    Args:
        connfd (socket): The socket connection file descriptor for the connected client.

    Side effects:
        Manages user sessions and coordinates with the backend for authentication and user management.
        Closes the client connection at the end of the session or in case of errors.
    """
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
            action = auth_info['action']
            
            if action == "Create User":
                if password == None:
                    if backenddashboard.check_user_taken(username):
                        connfd.sendall("Username taken".encode())
                        continue
                    elif not backenddashboard.is_valid_email(username):
                        connfd.sendall("Email not valid".encode())
                        continue
                    else:
                        connfd.sendall("Valid username".encode())
                        
                        response = connfd.recv(1024).decode()
                    
                        # verify email
                        # wait for password to be verified first
                        if response == "Valid password":
                            pin = backenddashboard.send_email_and_return_pin(username)
                            
                            connfd.sendall("Get PIN".encode())
                            
                            pin_to_verify = connfd.recv(1024).decode()
                            
                            email_verified = backenddashboard.verify_pin(pin_to_verify,pin)
                            
                            if email_verified: # email sent
                                connfd.sendall("Valid PIN".encode())
                                data = connfd.recv(1024)
                        
                                # Decode data from bytes to string
                                data_str = data.decode('utf-8')

                                # Parse JSON data
                                auth_info = json.loads(data_str)

                                # Extract username and password
                                username = auth_info['username']
                                password = auth_info['password']
                                verified = auth_info['verified']
                                
                                backenddashboard.create_user(2, username, password, verified)
                                log_action(connfd, username, username, "User", "Create User", "Success")

                                # username is valid now prompt for password
                                continue
                            else:
                                connfd.sendall("Invalid PIN".encode())
                                continue
                                               
            
            elif action == "Forgot password":
                email_to_check = username
                user_exists = backenddashboard.user_exists(email_to_check)
                if user_exists:
                    # generate pin and send
                    pin = backenddashboard.send_email_and_return_pin(email_to_check)
                    # verify pin
                    connfd.sendall("Get PIN".encode())
                    while True:  

                        pin_to_verify = connfd.recv(1024).decode()  
                        pin_verified = backenddashboard.verify_pin(pin_to_verify,pin)

                        if pin_verified:
                            # request new pw
                            connfd.sendall("Get new password".encode())
                            
                            new_password = connfd.recv(1024).decode()

                            role = backenddashboard.get_auth_level(email_to_check)
                            backenddashboard.update_pw(email_to_check, new_password, role)
                            
                            str_role = backenddashboard.get_auth_level_str(role)
                            
                            log_action(connfd, email_to_check, email_to_check, str_role, "Reset Password", "Success")
                            connfd.sendall("Password updated".encode())
                            break

                        else:
                            connfd.sendall("PIN not verified".encode())
                            continue

                    continue

                else:
                    connfd.sendall("User does not exist".encode())


            elif action == "Login":
                if password == None:
                    if backenddashboard.user_exists(username):
                        if backenddashboard.check_verify(username) and not (username in logged_in or username in admin_logged_in):
                            connfd.sendall("Verified".encode('utf-8'))
                            continue
                        
                        elif not (backenddashboard.check_verify(username)):
                            connfd.sendall("Not verified".encode('utf-8'))
                            if verify_pin_helper(connfd, username):
                                continue
                            else:
                                continue
                        
                            
                        elif username in logged_in or username in admin_logged_in:
                            connfd.sendall("You are logged in already".encode('utf-8'))
                            continue
                        
                        else:
                            connfd.sendall("auth".encode('utf-8'))
                    elif backenddashboard.is_valid_email(username):
                        connfd.sendall("Email not valid".encode())
                        continue
                    
                    else:
                        connfd.sendall("User does not exist".encode())
                        continue
                        
                else:

                    # authentication check
                    auth = backenddashboard.auth_login(username, password)
                    
                    if auth == "0":
                        print(f"Superadmin {username} authenticated successfully.")
                        clients[username] = connfd
                        admin_logged_in[username] = 'yes'
                        log_action(connfd, username, username, "Superadmin", "Log In", "Success")
                        print(f"{username} logged in.")
                        
                        connfd.sendall(str(auth).encode())
                        client_username = username
                        
                        try:

                            while True:
                                data = connfd.recv(1024)
                
                                # Decode data from bytes to string
                                data_str = data.decode('utf-8')

                                # Parse JSON data
                                auth_info = json.loads(data_str)

                                # Extract username and password
                                # this is the username they want to create or delete
                                username = auth_info['username']
                                action = auth_info['password']
                                
                                if action == "Create User":
                                    username, password = create_user_helper(connfd, username)
                                    print(username, password)
                                    if username:
                                        backenddashboard.create_user(2, username, password, False)
                                        log_action(connfd, username, client_username, "Superadmin", "Create User", "Success")
                                    else:
                                        continue
                                    
                                elif action == "Create Admin":
                                    username, password = create_user_helper(connfd, username)
                                    print(username, password)
                                    if username:
                                        backenddashboard.create_user(1, username, password, False)
                                        log_action(connfd, username, client_username, "Superadmin", "Create Admin", "Success")
                                    else:
                                        continue

                                elif action == "Delete":
                                    target_user = auth_info['target_user']
                                    status = backenddashboard.delete_user(username, target_user)
                                    if status == 0:
                                        connfd.sendall("Denied".encode())
                                        log_action(connfd, target_user, client_username, "Superadmin", "Delete Account", "Failed")

                                    elif status == 1:
                                        connfd.sendall("Success".encode())
                                        log_action(connfd, target_user, client_username, "Superadmin", "Delete Account", "Success")

                                       
                                    elif status == 2:
                                        connfd.sendall("User not found".encode())
                                        log_action(connfd, target_user, client_username, "Superadmin", "Delete Account", "Failed")
                                
                                elif action == "Logs":
                                    with open('server.log', 'rb') as log_file:
                                        while True:
                                            data = log_file.read(1024)  # Read in chunks of 1KB
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
                                log_action(connfd, username, username, "Superadmin", "Log Out", "Success")
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
                        log_action(connfd, username, username, "Admin", "Log In", "Success")
                        print(f"{username} logged in.")
                        
                        connfd.sendall(str(auth).encode()) 
                        admin_username = username
                        
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
                                    if username is not None:
                                        backenddashboard.create_user(2, username, password, False)
                                        log_action(connfd, username, admin_username, "Admin", "Create User", "Success")
                                    else:
                                        continue
                                    
                                elif action == "Create Admin":
                                    username, password = create_user_helper(connfd, username)
                                    if username:
                                        backenddashboard.create_user(1, username, password, False)
                                        log_action(connfd, username, admin_username, "Admin", "Create Admin", "Success")
                                    else:
                                        continue

                                elif action == "Delete":
                                    target_user = auth_info['target_user']
                                    status = backenddashboard.delete_user(username, target_user)

                                    if status == 0:
                                        log_action(connfd, target_user, admin_username, "Admin", "Delete Account", "Failed")
                                        connfd.sendall("Denied".encode())
                                    elif status == 1:
                                        log_action(connfd, target_user, admin_username, "Admin", "Delete Account", "Success")
                                        connfd.sendall("Success".encode())
                                        # if they are logged in they are logged out
                                    elif status == 2:
                                        log_action(connfd, target_user, admin_username, "Admin", "Delete Account", "Failed")
                                        connfd.sendall("User not found".encode())
                                
                                elif action == "Logs":
                                    with open('server.log', 'rb') as log_file:
                                        while True:
                                            data = log_file.read(1024) 
                                            if not data:
                                                break  # If no more data, stop the loop
                                            connfd.sendall(data)
                                        connfd.sendall(b"END_OF_FILE")
                                        
                                elif action == "END_SESSION_ADMIN":
                                    break
                                    
                        except Exception as e:
                            print(f"An error occurred: {e}")
                                    
                        finally:
                            print(f'{username} logged out')
                            try:
                                log_action(connfd, username, username, "Admin", "Log Out", "Success")
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
                        blocked_users[username] = []
                        print(f"{username} logged in.")
                        log_action(connfd, username, username, "User", "Log In", "Success")
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
                        log_action(connfd, username, username, failed_role, "Log In", "Failed")
                        connfd.sendall("Login failed.".encode())
                        break
            elif action == "end":
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
    finally:
        connfd.close()
        
        
def main():
    """
    The main server function that sets up the SSL socket, accepts incoming connections,
    and spawns new threads to handle these connections.

    Side effects:
        Continuously listens for incoming connections on a specified port, handling each connection
        with a separate thread. Handles server startup and shutdown procedures.
    """
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


