
import os
import socket
import hashlib
import easygui
import json
from os import _exit as quit
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
import base64
import string
import secrets
import csv
import pandas as pd
from collections import OrderedDict

current_new_userID = 0

# dummy_users = {
#     "bob": hashlib.sha256("password1".encode()).hexdigest(),
#     "samantha": hashlib.sha256("password2".encode()).hexdigest(),
# }

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

# def gen_csv(csv_file): # helper function for write_csv
#     columns = ["username", "userID", "password", "salt"]
#     print('file generated')
#     with open(csv_file, 'w', newline = '') as file:
#         writer = csv.writer(file)
#         writer.writerow(columns)

# def write_csv(file, userinfo):
#     # append to existing csv if it exists
#     if os.path.exists(file):
#         print('file found')
#         with open(file, 'a', newline = '') as csv_file:
#             writer = csv.writer(csv_file)
#             writer.writerow(userinfo)

#     # create new csv if does not exist
#     else:
#         print('file not found')
#         gen_csv(file)
#         with open(file, 'a', newline = '') as csv_file:
#             writer = csv.writer(csv_file)
#             writer.writerow(userinfo)

# def add_csv_record(file, dict):
#     # Write dictionary to CSV file
#     with open(file, 'a', newline='') as csvfile:
#         writer = csv.writer(csvfile)
#         writer.writerow(dict.values())

def isSpecialChar(char):
    special_chars = string.punctuation
    return char in special_chars

def isSpace(char):
    return char == ' '

# def valid_pw(password):
#     # password rules
#     pw_length = len(password) > 2
#     pw_num_count = sum(1 for c in password if c.isdigit()) > 0
#     pw_special_char_count = sum(1 for c in password if isSpecialChar(c)) > 0
#     pw_uppercase_count= sum(1 for c in password if c.isupper()) > 0
#     pw_space_count = sum(1 for c in password if isSpace(c)) < 1
    
#     return pw_length and pw_num_count and pw_special_char_count and pw_uppercase_count and pw_space_count

def gen_salt():
    # returns hex string
    salt = secrets.token_bytes(16)
    salt_hex = salt.hex()
    return salt_hex

# def get_auth_level(username):
#     df = read_csv_as_df()
#     row = df[df['username'] == username]
#     role = row["role"]
#     return int(role)

# def auth_action(user, target_user):
#     auth_level_deleter = get_auth_level(user)
#     auth_level_deletee = get_auth_level(target_user)
#     return auth_level_deleter < auth_level_deletee

# def entry_exists(username):
#     input_df = read_csv_as_df()
#     return (input_df['username'] == username).any()

# def read_csv_as_df():
#     filename = "userinfo.csv"
#     df = pd.read_csv(filename)
#     return df

# def df_to_csv(file, df):
#     df.to_csv(file, index = False)

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

    def user_menu(self, username):
        actions = ["Send Photo", "Block Users", "Delete your account", "Quit"]
        # user menu
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
                break
            
            return entered_username
        
    def password_login(self):
        while True:
            entered_password = easygui.passwordbox("Enter password", title = "Login")
            if entered_password is None:
                break
            
            return entered_password
        
        
    def get_pin(self):
        while (True):
            pin = easygui.passwordbox("Check your email and enter PIN:", 'Verify email')
            if pin is None:
                break
            return pin
        
    def create_user(self):
        while True:
            username = easygui.enterbox("Enter username:", "Create User")
            if username is None: # pressed cancel
                return None, None
            elif len(username.strip()) == 0:
                self.display_message("Username not valid.")
                continue
            password = easygui.passwordbox("Enter password", title = "Create User")
            if password is None: # pressed cancel
                return None, None
            return username, password
            
        
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
    
    def get_password(self, role):
        while (True):
            password = easygui.passwordbox("Enter password:", f'Create {role}')
            if password is None:
                break
            # check if password meets requirements
            if self.valid_pw(password):
                return password
            else:
                easygui.msgbox("Invalid password", f'Create {role}')
                continue
        return None

    def reset_get_password(self):
        while (True):
            password = easygui.passwordbox("Enter password:", "Reset password")
            if password is None:
                break
            # check if password meets requirements
            if self.valid_pw(password):
                return password
            else:
                easygui.msgbox("Invalid password")
                continue
        return None

    # def reset_self_password(self, user):
    #     userinfo_df = read_csv_as_df()
    #     print(userinfo_df)
    #     while(True):
    #         password = easygui.passwordbox("Enter new password:", "Reset password")
    #         if password is None:
    #             return None
    #         # check if password meets requirements
    #         if valid_pw(password):
    #             # update self
    #             self.update_pw(user, password)
    #             break
    #         else:
    #             easygui.msgbox("Invalid password", "Reset password")
    
    def valid_pw(self, password):
    # password rules
        pw_length = len(password) > 2
        pw_num_count = sum(1 for c in password if c.isdigit()) > 0
        pw_special_char_count = sum(1 for c in password if isSpecialChar(c)) > 0
        pw_uppercase_count= sum(1 for c in password if c.isupper()) > 0
        pw_space_count = sum(1 for c in password if isSpace(c)) < 1
        
        return pw_length and pw_num_count and pw_special_char_count and pw_uppercase_count and pw_space_count


    # def reset_user_password(self, user):
    #     userinfo_df = read_csv_as_df()
    #     print(userinfo_df)
    #     target_user = easygui.enterbox("Enter username of user to reset")

    #     if entry_exists(target_user):
    #         if auth_action(user, target_user):
    #             while(True):
    #                 password = easygui.passwordbox("Enter new password:", "Reset password")
    #                 if password is None:
    #                     return None
    #                 # check if password meets requirements
    #                 if valid_pw(password):
    #                     # delete old record
    #                     self.update_pw(target_user,password)
    #                     break
    #                 else:
    #                     easygui.msgbox("Invalid password", "Reset password")
    #         else:
    #             easygui.msgbox("Unauthorized action. Returning to menu...")
    #     else:
    #         easygui.msgbox("User does not exist. Returning to menu...")

    # def update_pw(self, target_user, password):
    #     input_df = read_csv_as_df()
    #     input_df[input_df['username'] != target_user]

    #     removed_user_df = input_df[input_df['username'] != target_user]
    #     print("removed user")
    #     #update csv with user removed
    #     df_to_csv("userinfo.csv", removed_user_df)

    #     # salt password
    #     salt = gen_salt()
    #     salt_password = password + salt
        
    #     # generate new user ID
    #     try:
    #         userinfo_df = read_csv_as_df()
    #         sorted_userinfo_df = userinfo_df.sort_values(by="userID")
    #         last_user_id = sorted_userinfo_df['userID'].iloc[-1]
    #         current_new_userID = last_user_id + 1
    #     except FileNotFoundError:
    #         current_new_userID = 0
    #     except IndexError:
    #         current_new_userID = 0
    #     except TypeError:
    #         current_new_userID = 0

    #     # hash salted password
    #     hash_obj = hashlib.sha256()
    #     hash_obj.update(salt_password.encode())
    #     hex_hash_salt_pw = hash_obj.hexdigest()
    
    #     # add to password csv
    #     new_userinfo = {"username":target_user, 
    #                     "userID":str(current_new_userID), 
    #                     "role":2,
    #                     "password":hex_hash_salt_pw,
    #                     "salt":salt,}

    #     add_csv_record("userinfo.csv",new_userinfo)
    #     easygui.msgbox("Password updated")
        # read csv and update user id tracker     

    