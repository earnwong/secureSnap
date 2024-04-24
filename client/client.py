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
end = "END_SESSION"

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
                get_loggedin_info = {'username': None, 'password': action}
                server_socket.sendall(json.dumps(get_loggedin_info).encode())
                
                # server_socket.sendall(action.encode())
                
                logged_in = server_socket.recv(1024)
                
                # Decode the bytes back to a string
                data_str = logged_in.decode('utf-8')
                
                # Convert the JSON string back to a dictionary
                logged_in_received = json.loads(data_str)
                print(logged_in_received)
                
                recipient = frontend_dashboard.select_user(logged_in_received, username)

                if recipient:
                    sending_info = {'username': recipient, 'password': action}
                    server_socket.sendall(json.dumps(sending_info).encode())
                    
                    # server_socket.sendall(recipient.encode())
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
            sending_info = {'username': None, 'password': end}
            server_socket.sendall(json.dumps(sending_info).encode())
            server_socket.close()
            _exit(0) # Exits the program
            
        
        elif action == "Delete":
            confirm_delete = easygui.buttonbox("Confirm action?", choices=["Confirm", "Cancel"], title = "Confirm?")
            if confirm_delete == 'Confirm':
                sending_info = {'username': username, 'password': action}
                server_socket.sendall(json.dumps(sending_info).encode())
                
                response = server_socket.recv(1024).decode('utf-8')
                if response == "User Removed":
                    server_socket.close()
                    _exit(0)
            else: 
                continue
        
        else:
            pause_event.set()
            print("Invalid action. Please try again.")
            
def createUserHelper(username, password, server_socket, role):
    # if password == "Create User": 
    # Send the username and action ("Create user") to the server
    
    login_info = {'username': username, 'password': password}
    server_socket.sendall(json.dumps(login_info).encode())
    
    print("SENT USERNAME")
    
    response = server_socket.recv(1024).decode()

    print("response from server", response)
    
    if response == "Username taken":
        #display username taken on gui
        frontend_dashboard.display_message("Username Taken. Try Again.")
        return
    
    elif response == "Valid":
        password = frontend_dashboard.get_password(role)
        
        if password is None:
            return None
        
        make_account = {'username': username, 'password': password}
        server_socket.sendall(json.dumps(make_account).encode())
        
        frontend_dashboard.display_message("User created successfully")
        
def delete_user_helper(username, action, target_user, server_socket):
    # username is the username they want to delete, password is the action
    login_info = {'username': username, 'password': action, 'target_user': target_user}
    
    # send the info to the server for checks and deletion
    server_socket.sendall(json.dumps(login_info).encode())
    
    response = server_socket.recv(1024).decode()
    
    if response == "Denied":
        frontend_dashboard.display_message("Permission denied: No authorization to delete this account. Returning to menu...")
    elif response == "Success":
        frontend_dashboard.display_message("User removed. Returning to menu...")
    elif response == "User not found":
        frontend_dashboard.display_message("User does not exist. Returning to menu...")

def parse_log_entries(log_data):
    entries = log_data.strip().split("\n")
    #print(entries)
    structured_entries = []
    for entry in entries:
        parts = entry.split(", ")
        
        entry_dict = {
            'Time': parts[0].split("Time: ")[1],
            'IP Address': parts[1].split("IP address: ")[1],
            'Username': parts[2].split("Username: ")[1],
            'Status': parts[3].split("Status: ")[1],
            'Action': parts[4].split("Action: ")[1],
            'Role': parts[5].split("Role: ")[1],
        }

        structured_entries.append(entry_dict)
    
    return structured_entries

def display_logs_paged(log_entries, page=0, entries_per_page=5):
    start_index = page * entries_per_page
    end_index = start_index + entries_per_page
    page_entries = log_entries[start_index:end_index]

    # Prepare headers and format string for more compact display
    headers = "Time                  | IP Addr    |  Username  | Status | Action     | Role"
    fmt = "{:<15} | {:<9} | {:<11} | {:<6} | {:<12} | {:<4}"
    lines = [headers] + [fmt.format(e['Time'], e['IP Address'], e['Username'], e['Status'], e['Action'], e['Role']) for e in page_entries]
    message = "\n".join(lines)

    # Append navigation text
    nav_text = f"Page {page + 1}/{(len(log_entries) + entries_per_page - 1) // entries_per_page}\n"
    message += nav_text + ("Previous " if start_index > 0 else "") + ("Next " if end_index < len(log_entries) else "") + "Quit"

    message = "\n".join(lines)

    # Append navigation instructions directly to the message
    navigation_instructions = f"\nPage {page + 1} of {len(log_entries) // entries_per_page + 1}\n"
    if start_index > 0:
        navigation_instructions += "Click 'Previous' to go to the previous page. "
    if end_index < len(log_entries):
        navigation_instructions += "Click 'Next' to go to the next page. "
    navigation_instructions += "Click 'Quit' to exit."

    message += navigation_instructions  # Add navigation text to the main message

    # Display in a buttonbox
    choice = easygui.buttonbox(msg=message, title="Log Viewer - Page {}".format(page + 1), choices=['Previous', 'Next', 'Quit'])

    if choice == "Next" and end_index < len(log_entries):
        display_logs_paged(log_entries, page + 1, entries_per_page)
    elif choice == "Previous" and start_index > 0:
        display_logs_paged(log_entries, page - 1, entries_per_page)
    elif choice == "Quit":
        return  # Quit or close the window

def view_log(username, action, server_socket):
    send_info = {'username': username, 'password': action}
    server_socket.sendall(json.dumps(send_info).encode())

    received_data = b""
    while True:
        data = server_socket.recv(1024)
        if data.endswith(b"END_OF_FILE"):
            break  # No more data is being sent from the server
        received_data += data
        received_data[:-len(b"END_OF_FILE")]

    log_contents = received_data.decode('utf-8')
    
    log_entries = parse_log_entries(log_contents)

    display_logs_paged(log_entries)

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
            while True:
                # Prompt user for username and password
                username, password = frontend_dashboard.login()
                print(username, password)
                
                if password == "Create User": 
                    # Send the username and action ("Create user") to the server
                    login_info = {'username': username, 'password': password}
                    server_socket.sendall(json.dumps(login_info).encode())
                    
                    response = server_socket.recv(1024).decode()
                    if response == "Username taken":
                        #display username taken on gui
                        frontend_dashboard.display_message("Username Taken. Try Again.")
                        continue
                    elif response == "Valid":
                        password = frontend_dashboard.get_password("user")
                        print(password)
                        
                        if password is None:
                            continue
                        
                        make_account = {'username': username, 'password': password}
                        server_socket.sendall(json.dumps(make_account).encode())
                        
                        frontend_dashboard.display_message("User created successfully")
                        
                        
                else:
                    login_info = {'username': username, 'password': password}
                    server_socket.sendall(json.dumps(login_info).encode())
                    break

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
                    server_socket.sendall("QUIT_AUTH_FAILED".encode())
                    server_socket.close()
                    _exit(0) # Exits the program
                else:
                    # Close the current connection and loop to retry login
                    server_socket.sendall("CONTINUE".encode())
                    server_socket.close()
            elif response == "User does not exist":
                frontend_dashboard.display_message("This user does not exist.")
            
            else:
                print("Unexpected response from server:", response)
                server_socket.close()
        
    
    if role == "0":
        while True:
            #print("IT GOES HERE GODDAMIT")
            action = frontend_dashboard.superadmin_menu(username)
            print(action)
            
            if action == "Create Admin":
                create_username = easygui.enterbox("Enter username:", "Create Admin")
                if create_username is None:
                    continue
                none_check = createUserHelper(create_username, action, server_socket, "admin")
                if none_check is None:
                    continue
                
            if action == "Create User":
                create_username = easygui.enterbox("Enter username:", "Create User")
                if create_username is None:
                    continue
                none_check = createUserHelper(create_username, action, server_socket, "user")
                if none_check is None:
                    continue
                
            if action == "Delete":
                target_user = easygui.enterbox("Enter username of user to delete")
                if target_user is None:
                    continue
                delete_user_helper(username, action, target_user, server_socket)
                
            if action == "Reset":
                # login_info = {'username': username, 'password': password}
                # server_socket.sendall(json.dumps(login_info).encode())
                return

            if action == "Logs":
                view_log(username, action, server_socket)
            
            if action == "end":
                send_info = {'username': username, 'password': "END_SESSION_SUPER_ADMIN"}
                server_socket.sendall(json.dumps(send_info).encode())
                server_socket.close()
                _exit(0) # Exits the program
            
    
    if role == "1":
        while True:
            action = frontend_dashboard.admin_menu(username)
            
            if action == "Create Admin":
                create_username = easygui.enterbox("Enter username:", "Create Admin")
                if create_username is None:
                    continue
                none_check = createUserHelper(create_username, action, server_socket, "admin")
                if none_check is None:
                    continue
            
            if action == "Create User":
                create_username = easygui.enterbox("Enter username:", "Create User")
                if create_username is None:
                    continue
                none_check = createUserHelper(create_username, action, server_socket, "user")
                if none_check is None:
                    continue
                
            if action == "Delete":
                target_user = easygui.enterbox("Enter username of user to delete")
                if target_user is None:
                    continue
                delete_user_helper(username, action, target_user, server_socket)
            
            if action == "Reset User password":
                return
            
            if action == "Logs":
                view_log(username, action, server_socket)

            if action == "end":
                send_info = {'username': username, 'password': "END_SESSION_ADMIN"}
                server_socket.sendall(json.dumps(send_info).encode())
                server_socket.close()
                _exit(0)
                
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
