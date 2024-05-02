
import easygui
import json
from os import _exit as quit
import string
import secrets
import pandas as pd


current_new_userID = 0


# helper functions
def write_json(file,userinfo):
    with open(file, 'w') as json_file:
        json.dump(userinfo, json_file, indent=4)

def read_json(file,userinfo):
    try:
        with open(file, 'r') as json_file:
            data = json.load(json_file)
    except FileNotFoundError:
        if userinfo is not None:
            write_json('userinfo.json',userinfo)
        data = userinfo
    return data


def isSpecialChar(char):
    special_chars = string.punctuation
    return char in special_chars

def isSpace(char):
    return char == ' '

def gen_salt():
    # returns hex string
    salt = secrets.token_bytes(16)
    salt_hex = salt.hex()
    return salt_hex


class FrontendDashboard:
    def __init__(self):
        pass
        
    # superadmin menu
    def superadmin_menu(self, username):
        actions = ["Create Admin", "Create User", "Delete Admin/User", "View Logs", "Quit"]
        while True:
            action = easygui.buttonbox("Choose an action:", choices = actions, title=f'Welcome (0) Superadmin:{username}!')
            if action == "Create Admin":
                return action
            if action == "Create User":
                return action
            if action == "Delete Admin/User":
                return "Delete"
            if action == "View Logs":
                return "Logs"
            if action == "Quit":
                return "end"

    # admin menu
    def admin_menu(self, username):
        actions = ["Create Admin","Create User", "Delete User", "View Logs", "Quit"]
        while True:
            action = easygui.buttonbox("Choose an action:", choices = actions, title=f'Welcome (1) Admin: {username}!')
            if action == "Create Admin":
                return action
                # self.create_user(1)
            if action == "Create User":
                return action
                # self.create_user(2)
            if action == "Delete User":
                return "Delete"
                # self.delete_user(username)
            if action == "View Logs":
                return "Logs"
                # self.reset_user_password(username)
            if action == "Quit":
                return "end"

    # user menu
    def user_menu(self, username):
        actions = ["Send Photo", "Block Users", "Delete your account", "Quit"]
        while True:
            action = easygui.buttonbox("Choose an action:", choices = actions, title=f'Welcome (2) User: {username}!')
            if action == "Send Photo":
                return "send"
            if action == "Block Users":
                return "block"
            if action == "Delete your account":
                return "Delete"
            if action == "Quit":
                return "end"
            
        
    def landing_page(self): # return password and username
        actions = ["Login","Create User", "Forgot password", 'Quit']
        action = easygui.buttonbox("Choose an action:", choices = actions)
        if action == 'Quit':
            return "end"
        else:
            return action
        
    def get_email(self):
        while True:
            entered_username = easygui.enterbox("Enter username: ", title="Login")
            if entered_username is None:
                break
            return entered_username

    def username_login(self):
        while True:
            entered_username = easygui.enterbox("Enter username: ", title="Login")
            if entered_username is None:
                return None
            
            return entered_username
        
    def password_login(self):
        while True:
            entered_password = easygui.passwordbox("Enter password", title = "Login")
            if entered_password is None:
                return None
            
            return entered_password
        
        
    def get_pin(self):
        while (True):
            pin = easygui.passwordbox("Check your email and enter PIN:", 'Verify email')
            if pin is None:
                break
            return pin
        
    def create_user_getusername(self):
        while True:
            username = easygui.enterbox("Enter username:", "Create User")
            if username is None: # pressed cancel
                return None, None
            elif len(username.strip()) == 0:
                self.display_message("Username not valid.")
                continue
            
            return username
    
    def create_user_getpassword(self):
        while True:
            password = easygui.passwordbox("Enter password", title = "Create User")
            if not self.valid_pw(password):
                easygui.msgbox("Invalid password. Password should be between 8 - 32 characters, 1 number, 1 special character, 1 uppercase character and no spaces.")
                continue
            
            if password is None: # pressed cancel
                return None, None
            
            return password
            
        
    def select_user(self, logged_in, username):
        # Exclude the current user from the selection
        if username in logged_in:
            del logged_in[username]  # Remove current user from the list once

        username_list = list(logged_in.keys())
        username_list.append("Return to Main Menu")

        # If there's only the "Return to Main Menu" option, inform the user and exit
        if len(username_list) == 1:
            easygui.msgbox("There are no other users available.", title="User Selection")
            return None

        selected_user = easygui.choicebox(msg="Select a User", title="User Selection", choices=username_list)

        if selected_user == "Return to Main Menu" or selected_user is None:
            easygui.msgbox("Returning to the main menu.", title="User Selection")
            return None

        # If a valid selection is made, return it
        return selected_user

    def display_message(self, msg):
        easygui.msgbox(msg, title="User Selection")
    

    def reset_get_password(self):
        while (True):
            password = easygui.passwordbox("Enter password:", "Reset password")
            if password is None:
                break
            # check if password meets requirements
            if self.valid_pw(password):
                return password
            else:
                easygui.msgbox("Invalid password. Password should be between 8 - 32 characters, 1 number, 1 special character, 1 uppercase character and no spaces.")
                continue
        return None

    
    def valid_pw(self, password):
    # password rules
        pw_length = len(password) > 7 and len(password) < 33
        pw_num_count = sum(1 for c in password if c.isdigit()) > 0
        pw_special_char_count = sum(1 for c in password if isSpecialChar(c)) > 0
        pw_uppercase_count= sum(1 for c in password if c.isupper()) > 0
        pw_space_count = sum(1 for c in password if isSpace(c)) < 1
        
        return pw_length and pw_num_count and pw_special_char_count and pw_uppercase_count and pw_space_count

  

    