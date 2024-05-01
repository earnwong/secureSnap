import sys
import socket
from os import _exit 
from dashboard import Dashboard
# from server.encrypt import EncryptDecrypt
# from Crypto.Cipher import PKCS1_OAEP
# from Crypto.PublicKey import RSA
import json
from frontenddashboard2 import FrontendDashboard
import time
import threading
import select
import ssl
import easygui
import tkinter as tk
from tkinter import ttk
# import struct
from queue import Queue
import secrets
import string



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
        time.sleep(10)
        event_set = pause_event.is_set()
        while event_set:
            event_set = pause_event.is_set()
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


        print("Action:", action)


        if action == "send":
            pause_event.set()
            print("Pause event when I click send:", pause_event.is_set())
            
            try:
                get_loggedin_info = {'username': None, 'password': action}
                server_socket.sendall(json.dumps(get_loggedin_info).encode())
                
                # server_socket.sendall(action.encode())
                
                logged_in = server_socket.recv(1024)
                
                # Decode the bytes back to a string
                data_str = logged_in.decode('utf-8')
                
                # Convert the JSON string back to a dictionary
                logged_in_received = json.loads(data_str)
                #print(logged_in_received)
                
                recipient = frontend_dashboard.select_user(logged_in_received, username)

                if recipient:
                    sending_info = {'username': recipient, 'password': action}
                    server_socket.sendall(json.dumps(sending_info).encode())
                    
                    # server_socket.sendall(recipient.encode())
                    response = server_socket.recv(22).decode('utf-8')
                
                    if response == "This user is available":

                            
                        frontend_dashboard.display_message("This user is available")
                
                        file_path = d.select_photo()
                        d.send_photo(file_path, recipient)
                    
                    elif response == "Blocked":
                        frontend_dashboard.display_message("This user is not available")
                    else:
                        print(response)
            finally:
                pause_event.clear()

        elif action == "block":
            pause_event.set()
            try:
                target_user = easygui.enterbox("Enter username of user to block")
                if target_user is None:
                    #server_socket.recv(1)
                    get_loggedin_info = {'username': None, 'password': action}
                    server_socket.sendall(json.dumps(get_loggedin_info).encode())
                    continue
                else: 
                    #server_socket.recv()
                    get_loggedin_info = {'username': username, 'password': action}
                    server_socket.sendall(json.dumps(get_loggedin_info).encode())
                    #print("target user:", target_user)
                    server_socket.sendall(target_user.encode())
                    status = server_socket.recv(1024).decode()
                    #status = int(status)
                    print("status:", status)
                    blockUserHelper(status)
            #time.sleep(10)
            finally:
                pause_event.clear()

        elif action == "end":
            pause_event.set()
            sending_info = {'username': None, 'password': end}
            print("i can go into end")
            server_socket.sendall(json.dumps(sending_info).encode())
            print("i send something")
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

def generate_random_password(length=12):
    # A strong password with letters, digits, and special characters
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for i in range(length))
    return password

def createUserHelper(username, password, server_socket, role):
    # if password == "Create User": 
    # Send the username and action ("Create user") to the server
    
    login_info = {'username': username, 'password': password}
    server_socket.sendall(json.dumps(login_info).encode())
        
    response = server_socket.recv(1024).decode()

    # print("response from server", response)
    
    if response == "Username taken":
        #display username taken on gui
        frontend_dashboard.display_message("Username Taken. Try Again.")
        return
    
    elif response == "Email not valid":
        frontend_dashboard.display_message("Not a valid email. Try Again.")
        return
                
    elif response == "Valid":
        # generate random password
        password = generate_random_password()
        
        frontend_dashboard.display_message("Generating Random Password...")
        
        make_account = {'username': username, 'password': password}
        server_socket.sendall(json.dumps(make_account).encode())
        
        frontend_dashboard.display_message("User created successfully")
        
def blockUserHelper(status):
    #login_info = {'username': username, 'password': action, 'target_user': target_user}
    #server_socket.sendall(json.dumps(login_info).encode())
    #response = server_socket.recv(1024).decode()
    status = int(status)
    if status == 0:
        frontend_dashboard.display_message("Permission denied: No authorization to block this account. Returning to menu...")
    elif status == 1:
        frontend_dashboard.display_message("Successfully blocked this user. Returning to menu...")
    elif status == 2:
        frontend_dashboard.display_message("User does not exist. Returning to menu...")

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
            'Time': parts[0].split("Time: ")[1].strip(),
            'IP Address': parts[1].split("IP address: ")[1].strip(),
            'Username': parts[2].split("Username: ")[1].strip(),
            'Status': parts[3].split("Status: ")[1].strip(),
            'Action': parts[4].split("Action: ")[1].strip(),
            'Done By': parts[5].split("Done By: ")[1].strip(),
            'Role': parts[6].split("Role: ")[1].strip(),
        }

        structured_entries.append(entry_dict)
    
    return structured_entries

def display_logs(logs):
    root = tk.Tk()
    root.title("Log Viewer")

    tree = ttk.Treeview(root, columns=('Time', 'IP Address', 'Username', 'Status', 'Action', 'Done By', 'Role'), show='headings')
    for col in tree['columns']:
        tree.heading(col, text=col)

    for log in logs:
        tree.insert("", tk.END, values=(log['Time'], log['IP Address'], log['Username'], log['Status'], log['Action'], log['Done By'], log['Role']))
    
    tree.pack(expand=True, fill=tk.BOTH)
    root.mainloop()

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

    display_logs(log_entries)
    
    
def verify_pin_helper(server_socket):
    response = server_socket.recv(1024).decode()
    print("response verify pin helper", response)
    if response == "Get PIN":
        print("get pin - line 303")
        while True:
            # pin_to_verify = frontend_dashboard.get_pin()
            pin_to_verify = easygui.passwordbox("Check your email and enter PIN:", 'Verify email')
            print("first time")
            
            if pin_to_verify is None:
                # server_socket.sendall("Cancel".encode())
                return False

            server_socket.sendall(pin_to_verify.encode())
            
            response = server_socket.recv(1024).decode()

            if response == "Get new password":
                new_password = frontend_dashboard.reset_get_password() # validates pw
                
                server_socket.sendall(new_password.encode())

                response = server_socket.recv(1024).decode()

                if response == "Password updated":
                    frontend_dashboard.display_message("Password updated")
                    return True

            elif response == "PIN not verified":
                print("incorrect pin")
                frontend_dashboard.display_message("Incorrect Pin. Try Again")
                continue
            


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
                action = frontend_dashboard.landing_page()
                
                if action == "Login":
                    username = frontend_dashboard.username_login()
                    
                    login_info = {'username': username, 'password': None, 'action': "Login"}
                    server_socket.sendall(json.dumps(login_info).encode())
                    
                    response = server_socket.recv(1024).decode()
                    
                    if response == "You are logged in already":
                        frontend_dashboard.display_message("You are already logged in.")
                        continue
                    
                    elif response == "auth":
                        continue
                    
                    elif response == "Verified":
                        password = frontend_dashboard.password_login()
                        login_info = {'username': username, 'password': password, 'action': "Login"}
                        server_socket.sendall(json.dumps(login_info).encode())
                        break
                        
                    elif response == "Not verified":
                        frontend_dashboard.display_message("You have not verified your account.")
                        if verify_pin_helper(server_socket):
                            continue # pin is verified and they can log in properly
                        else:
                            print("Invalid PIN entered. Please try again.")
                            continue
                    elif response == "User does not exist":
                        frontend_dashboard.display_message("This user does not exist")
                        continue
                    elif response == "Email not valid":
                        frontend_dashboard.display_message("Not a valid email. Try Again.")
                        continue
                    

                elif action == "Create User": 
                    username, password = frontend_dashboard.create_user()
                    
                    if username is None:
                        continue
                    
                    print(username, password)
                    
                    # STEP 1 - send username
                    auth_info = {'username': username, 'password': password, 'action': "Create User"}
                    print(auth_info)
                    server_socket.sendall(json.dumps(auth_info).encode())
                    print("login info sent")
                    
                    response = server_socket.recv(1024).decode()
                    print(response)

                    if response == "Username taken":
                        #display username taken on gui
                        frontend_dashboard.display_message("Username Taken. Try Again.")
                        continue
                    elif response == "Email not valid":
                        frontend_dashboard.display_message("Not a valid email. Try Again.")
                        continue
                    
                    elif response == "Valid username":
                        # verify 
                        while True: # repeat until valid pw is entered
                            if frontend_dashboard.valid_pw(password):
                                # STEP 3 - IF PW VALID, SEND USERNAME, PW for username to be verified by server
                                server_socket.sendall("Valid password".encode())
                                response = server_socket.recv(1024).decode()
                                print(response)
                                
                                if response == "Get PIN": 
                                    pin_to_verify = frontend_dashboard.get_pin()
                                    server_socket.sendall(pin_to_verify.encode())
                                    response = server_socket.recv(1024).decode()
                                    print(response)

                                    if response == "Invalid PIN":
                                        frontend_dashboard.display_message("Invalid PIN. Try Again.")
                                        continue

                                    if response == "Time up":
                                        frontend_dashboard.display_message("You took too long to input the PIN. Returning to menu...")
                                        continue

                                    else: # valid PIN, email verified
                                    # email verification goes here -- stuff to do once email verified by server
                                        make_account = {'username': username, 'password': password, 'verified': True}
                                        server_socket.sendall(json.dumps(make_account).encode())
                                        
                                        frontend_dashboard.display_message("User created successfully")
                                        break


                elif action == "Forgot password":
                    username = frontend_dashboard.get_email()

                    login_info = {'username': username, 'password': None, 'action': "Forgot password"}
                    server_socket.sendall(json.dumps(login_info).encode())

                    response = server_socket.recv(1024).decode()
                    if response == "Get PIN":

                        while True:
                            pin_to_verify = frontend_dashboard.get_pin()
                            if pin_to_verify == None:
                                break

                            server_socket.sendall(pin_to_verify.encode())
                            
                            response = server_socket.recv(1024).decode()

                            if response == "Get new password":
                                new_password = frontend_dashboard.reset_get_password() # validates pw
                                
                                server_socket.sendall(new_password.encode())

                                response = server_socket.recv(1024).decode()

                                if response == "Password updated":
                                    frontend_dashboard.display_message("Password updated")
                                    break

                                continue

                            elif response == "PIN not verified":
                                frontend_dashboard.display_message("Incorrect Pin. Try Again")
                                continue

                    elif response == "User does not exist":
                        frontend_dashboard.display_message("User does not exist. Returning to menu...")
                        continue
                
                elif action == "end":
                    login_info = {'username': None, 'password': None, 'action': "end"}
                    server_socket.sendall(json.dumps(login_info).encode())
                    server_socket.close()
                    _exit(0) # Exits the program
                    
    
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
