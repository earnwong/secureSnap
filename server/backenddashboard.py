import easygui
import hashlib
import pandas as pd
import secrets
import csv


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
        role = row["role"]
        return int(role)
    
    def auth_login(self, entered_username, entered_password):
        userinfo_df = self.read_csv_as_df()
        
        # check if record exists in userinfo.csv
        entry_exists = (userinfo_df['username'] == entered_username).any()

        if entry_exists:
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
                return None
        
        else:
            return "User does not exist."
        
    # def valid_pw(password):
    #     # password rules
    #     pw_length = len(password) > 2
    #     pw_num_count = sum(1 for c in password if c.isdigit()) > 0
    #     pw_special_char_count = sum(1 for c in password if isSpecialChar(c)) > 0
    #     pw_uppercase_count= sum(1 for c in password if c.isupper()) > 0
    #     pw_space_count = sum(1 for c in password if isSpace(c)) < 1
        
    #     return pw_length and pw_num_count and pw_special_char_count and pw_uppercase_count and pw_space_count
    
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
    
    def create_user(self, role, username, password):
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
                        "salt":salt,}

        self.add_csv_record("userinfo.csv", new_userinfo)
        # read csv and update user id tracker