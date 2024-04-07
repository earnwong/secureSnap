
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

dummy_users = {
    "bob": hashlib.sha256("password1".encode()).hexdigest(),
    "samantha": hashlib.sha256("password2".encode()).hexdigest(),
}

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

def gen_csv(csv_file): # helper function for write_csv
    columns = ["username", "userID", "password", "salt"]
    print('file generated')
    with open(csv_file, 'w', newline = '') as file:
        writer = csv.writer(file)
        writer.writerow(columns)

def write_csv(file, userinfo):
    # append to existing csv if it exists
    if os.path.exists(file):
        print('file found')
        with open(file, 'a', newline = '') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(userinfo)

    # create new csv if does not exist
    else:
        print('file not found')
        gen_csv(file)
        with open(file, 'a', newline = '') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(userinfo)

def add_csv_record(file, dict):

    # Write dictionary to CSV file
    with open(file, 'a', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(dict.values())

def isSpecialChar(char):
    special_chars = string.punctuation
    return char in special_chars

def isSpace(char):
    return char == ' '

def valid_pw(password):
    # password rules
    pw_length = len(password) > 2
    pw_num_count = sum(1 for c in password if c.isdigit()) > 0
    pw_special_char_count = sum(1 for c in password if isSpecialChar(c)) > 0
    pw_uppercase_count= sum(1 for c in password if c.isupper()) > 0
    pw_space_count = sum(1 for c in password if isSpace(c)) < 1
    
    return pw_length and pw_num_count and pw_special_char_count and pw_uppercase_count and pw_space_count

def gen_salt():
    # returns hex string
    salt = secrets.token_bytes(16)
    salt_hex = salt.hex()
    return salt_hex

def auth_login(entered_username, entered_password, df):
    # check if record exists in userinfo.csv
    userinfo_df = read_csv_as_df()
    entry_exists = (userinfo_df['username'] == entered_username).any()

    if entry_exists:
        # get row of desired userinput
        row = df[df['username'] == entered_username]

        stored_hex_hash_salt_pw = row['password'].iloc[0]
        # salt userinput
        entered_salt_pw = entered_password + row["salt"].iloc[0]

        # hash salted userinput 
        hash_obj = hashlib.sha256()
        hash_obj.update(entered_salt_pw.encode())
        entered_hex_hash_salt_pw = hash_obj.hexdigest()

        # check if salted and hased UI matches stored salted and hashed UI
        if stored_hex_hash_salt_pw == entered_hex_hash_salt_pw:
            print('auth')
            return True
        else:
            print('no auth')
            easygui.msgbox("Incorrect password")
            quitbox = easygui.buttonbox("Quit?", choices = ["Quit","Continue"])
            if quitbox == "Quit":
                quit()
            return False
    
    else:
        easygui.msgbox("User does not exist")
        quitbox = easygui.buttonbox("Quit?", choices = ["Quit","Continue"])
        if quitbox == "Quit":
            quit()
        return False

def read_csv_as_df():
    filename = "userinfo.csv"
    df = pd.read_csv(filename)
    return df

def df_to_csv(file, df):
    df.to_csv(file, index = False)

class FrontendDashboard:
    def menu(self):
        actions = ["Select Photo", "Select User", "Delete User", "Quit"]

        while True:
            action = easygui.buttonbox("Choose an action:", choices = actions)
            if action == "Select Photo":
                self.select_photo()
            if action == "Select User":
                self.select_user()
            if action == "Delete User":
                self.delete_user()
            if action == "Quit":
                quit()

    def login(self):
        actions = ["Login","Create user"]

        while True:
            action = easygui.buttonbox("Choose an action:", choices = actions)
            if action == "Login":
                while True:
                    entered_username = easygui.enterbox("Enter username: ", title="Login")
                    entered_password = easygui.passwordbox("Enter password", title = "Login")
                    # easygui.msgbox(f"Username: {entered_username}\nPassword: {entered_password}")
                    df = read_csv_as_df()
                    # print(df)
                    if auth_login(entered_username, entered_password, df):
                        self.menu()
                    else:
                        continue
            if action == "Create user":
                self.create_user()

    def select_photo(self):
        file_path = easygui.fileopenbox(msg="Select a file to send", title="Select File")

        if file_path:
            with open(file_path, 'rb') as file:
                while True:
                    chunk = file.read(1024)  # Read the file in chunks of 1024 bytes
                    if not chunk:
                        break  # If no more data, stop the loop
                # print("File sent successfully.")
        else:
            print("No file selected.")
        
    def select_user(self):
        username_list = list(dummy_users.keys())  # Extract the usernames from the dummy_users dictionary
        selected_user = easygui.choicebox(msg="Select a User", title="User Selection", choices=username_list)
        return selected_user
    
    def create_user(self):
        while (True):
            username = easygui.enterbox("Enter username:", "Create User")
            # check if username exists
            userinfo_df = read_csv_as_df()
            entry_exists = (userinfo_df['username'] == username).any()
            if not entry_exists:
                break
            if username is None:
                return None
            else:
                easygui.msgbox("Username taken")

        while (True):
            password = easygui.passwordbox("Enter password:", "Create User")
            if password is None:
                return None
            # check if password meets requirements
            if valid_pw(password):
                break
            else:
                easygui.msgbox("Invalid password", "Create User")
        
        # salt password
        salt = gen_salt()
        salt_password = password + salt
        
        # generate new user ID
        try:
            userinfo_df = read_csv_as_df()
            sorted_userinfo_df = userinfo_df.sort_values(by="userID")
            last_user_id = sorted_userinfo_df['userID'].iloc[-1]
            current_new_userID = last_user_id + 1
        except FileNotFoundError:
            current_new_userID = 0
        except IndexError:
            current_new_userID = 0
        except TypeError:
            current_new_userID = 0

        # hash salted password
        hash_obj = hashlib.sha256()
        hash_obj.update(salt_password.encode())
        hex_hash_salt_pw = hash_obj.hexdigest()
    
        # add to password csv
        new_userinfo = {"username":username, 
                        "userID":str(current_new_userID), 
                        "password":hex_hash_salt_pw,
                        "salt":salt}

        add_csv_record("userinfo.csv",new_userinfo)
        easygui.msgbox("User created")


        # read csv and update user id tracker

    def delete_user(self):
        input_df = read_csv_as_df()
        print(input_df)
        user_to_delete = easygui.enterbox("Enter username of user to delete")
        entry_exists = (input_df['username'] == user_to_delete).any()
        while (True):
            if entry_exists:
                # update df with user removed
                removed_user_df = input_df[input_df['username'] != user_to_delete]
                print("removed user")
                #update csv with user removed
                df_to_csv("userinfo.csv", removed_user_df)
                easygui.msgbox("User removed")
                break
            else:
                easygui.msgbox("User does not exist")
                break
            
def main():
    d = FrontendDashboard()
    d.login()
    d.menu()
    # d.create_user()
    # d.delete_user()
    df = read_csv_as_df()
    print(df)

main()

# d = Dashboard()
# d.create_user()