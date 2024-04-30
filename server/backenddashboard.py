import easygui
import hashlib
import pandas as pd
import secrets
import csv
from email.message import EmailMessage
import smtplib
import random
import string


class BackendDashboard():
    def __init__(self) -> None:
        pass

    def read_csv_as_df(self):
        filename = "userinfo.csv"
        df = pd.read_csv(filename)
        return df

    def get_auth_level(self, username):
        df = self.read_csv_as_df()
        row = df[df['username'] == username]
        #role = row["role"]
        return row.iloc[0]["role"]
    
    def auth_login(self, entered_username, entered_password):
        userinfo_df = self.read_csv_as_df()
        
        # check if record exists in userinfo.csv
        entry_exists = (userinfo_df['username'] == entered_username).any()
        
        if entry_exists:
            print("entry exists")
            auth_level = self.get_auth_level(entered_username)
            # get row of desired userinput
            row = userinfo_df[userinfo_df['username'] == entered_username]

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
                return str(auth_level)
            else:
                print('no auth')
                return ("Failed", str(auth_level))
        
        else:
            print("user does not exist")
            return "User does not exist"
    
    def check_user_taken(self, username):
        while (True):
            # check if username exists
            userinfo_df = self.read_csv_as_df()
            entry_exists = (userinfo_df['username'] == username).any()
            if not entry_exists:
                break
            if username is None:
                return False
            else:
                return True
    
    def gen_salt(self):
        # returns hex string
        salt = secrets.token_bytes(16)
        salt_hex = salt.hex()
        return salt_hex

    def add_csv_record(self, file, dict):
        # Write dictionary to CSV file
        with open(file, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(dict.values())
    
    def create_user(self, role, username, password, verified):
        # salt password
        salt = self.gen_salt()
        salt_password = password + salt
        
        # generate new user ID
        try:
            userinfo_df = self.read_csv_as_df()
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
                        "role":role,
                        "password":hex_hash_salt_pw,
                        "salt":salt,
                        "verified":verified}

        self.add_csv_record("userinfo.csv", new_userinfo)
        # read csv and update user id tracker
        
    def entry_exists(self, username, input_df):
        return (input_df['username'] == username).any()

    def df_to_csv(self, file, df):
        df.to_csv(file, index = False)
    
    def auth_action(self, user, target_user):
        auth_level_deleter = self.get_auth_level(user)
        auth_level_deletee = self.get_auth_level(target_user)
        return auth_level_deleter <= auth_level_deletee
    
    def check_blocked_user(self, user, user_to_block):
        input_df = self.read_csv_as_df()
        if self.entry_exists(user_to_block, input_df):
            if self.auth_action(user, user_to_block):
                return 1 # can block user
            else:
                return 0 # cannot block user (permission denied)
        else:
            return 2 # user_to_block doesn't exist

    def delete_user(self, user, target_user):
        # delete confirmation        
        input_df = self.read_csv_as_df()
        
        if self.entry_exists(target_user, input_df):
            if self.auth_action(user, target_user):
                # update df with user removed
                removed_user_df = input_df[input_df['username'] != target_user]
                print("removed user")
                #update csv with user removed
                self.df_to_csv("userinfo.csv", removed_user_df)
                return 1 # successful
            else:
                return 0 # permission denied
        else:
            return 2 # user does not exist
        
    def delete_self(self, username):
        input_df = self.read_csv_as_df()
        removed_user_df = input_df[input_df['username'] != username]
        print("removed user")
        # update csv with user removed
        self.df_to_csv("userinfo.csv", removed_user_df)
        return True
    
    def send_email_and_return_pin(self, email_to_verify):
        pin = self.generate_pin()
        self.send_ver_email(email_to_verify, pin)
        return pin

    
    def get_pin(self):
        while (True):
            pin = easygui.passwordbox("Check your email and enter PIN:", 'Verify email')
            if pin is None:
                break
            return pin

    def verify_pin(self, pin_to_verify, pin):
  
        while (True):
            if pin_to_verify is None:
                break
            if pin_to_verify == pin:
                return True
            else:
                return False
        return None

    def generate_pin(self, length=6):
        return ''.join(random.choices(string.digits, k=length))

    def send_ver_email(self,recipient_email,pin):
        sender_email = "securesnap7@gmail.com"
        recipient_email = recipient_email
        subject = 'SecureSnap: Verify your email'
        sender_pw = "rajxmnmbhvfnempj"
        pin = pin
        body = ("PIN: " + str(pin))

        email = EmailMessage()
        email['From'] = sender_email
        email['To'] = recipient_email
        email['Subject'] = subject
        email.set_content(body)

        server = smtplib.SMTP('smtp.gmail.com',587)
        server.starttls()
        server.login(sender_email,sender_pw)

        server.sendmail(sender_email,recipient_email,email.as_string())
        print('mail sent')