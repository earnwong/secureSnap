import hashlib
import pandas as pd
import secrets
import csv
from email.message import EmailMessage
import smtplib
import random
import string
from email_validator import validate_email, EmailNotValidError


class BackendDashboard():
    """A class to handle backend operations for a user management system,
    including user authentication, email verification, and CSV database management."""
    
    def __init__(self) -> None:
        """Initialize the BackendDashboard class."""
        pass

    def read_csv_as_df(self):
        """Reads a CSV file into a pandas DataFrame.
        
        Returns:
            pandas.DataFrame: A DataFrame containing user information.
        """
        filename = "userinfo.csv"
        df = pd.read_csv(filename)
        return df

    def get_auth_level(self, username):
        """Retrieves the authorization level for a given username.
        
        Args:
            username (str): The username whose authorization level is to be retrieved.
        
        Returns:
            str: The authorization level of the user.
        """
        
        df = self.read_csv_as_df()
        row = df[df['username'] == username]
        #role = row["role"]
        return row.iloc[0]["role"]
    
    def get_auth_level_str(self, role):
        """Converts a numerical role to a string representation.
        
        Args:
            role (int): The numerical role.
        
        Returns:
            str: The string representation of the role.
        """
        
        if role == 0:
            return "superadmin"
        elif role == 1:
            return "admin"
        else:
            return "user"
        
    def check_verify(self, username):
        """Checks if a user's email is verified.
        
        Args:
            username (str): The username to check for verification.
        
        Returns:
            bool: True if the user's email is verified, otherwise False.
        """
        
        userinfo_df = self.read_csv_as_df()
        user_row = userinfo_df[userinfo_df['username'] == username]
        verify = user_row['verified'].iloc[0]
        
        return verify
            
    def user_exists(self, username):
        """Checks if a username exists in the user database.
        
        Args:
            username (str): The username to check.
        
        Returns:
            bool: True if the username exists, otherwise False.
        """
        userinfo_df = self.read_csv_as_df()
        entry_exists = (userinfo_df['username'] == username).any()
        return entry_exists
    
    def auth_login(self, entered_username, entered_password):
        """Authenticates a user based on username and password.
        
        Args:
            entered_username (str): The username to authenticate.
            entered_password (str): The password to authenticate.
        
        Returns:
            str: The user's authorization level if authentication is successful, otherwise an error message.
        """
        
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
                return str(auth_level)
            else:
                return ("Failed", str(auth_level))
        
        else:
            return "User does not exist"
    
    def check_user_taken(self, username):
        """Checks if a username is already taken in the database.
        
        Args:
            username (str): The username to check.
        
        Returns:
            bool: True if the username is taken, otherwise False.
        """
        
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
        """Generates a cryptographic salt.
        
        Returns:
            str: A hexadecimal representation of the salt.
        """
        # returns hex string
        salt = secrets.token_bytes(16)
        salt_hex = salt.hex()
        return salt_hex

    def add_csv_record(self, file, dict):
        """Adds a record to a CSV file.
        
        Args:
            file (str): The file path to the CSV.
            dict (dict): The dictionary containing user data to write.
        """
        
        # Write dictionary to CSV file
        with open(file, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(dict.values())
    
    def create_user(self, role, username, password, verified):
        """Creates a new user and adds their information to the CSV database.
        
        Args:
            role (int): The role of the user.
            username (str): The username of the new user.
            password (str): The password of the new user.
            verified (bool): Indicates whether the user's email is verified.
        """
        
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
        """Checks if a username exists in the given DataFrame.
        
        Args:
            username (str): The username to check.
            input_df (pandas.DataFrame): The DataFrame to search in.
        
        Returns:
            bool: True if the username exists in the DataFrame, otherwise False.
        """
        return (input_df['username'] == username).any()

    def df_to_csv(self, file, df):
        """Writes a DataFrame to a CSV file.
        
        Args:
            file (str): The file path to write to.
            df (pandas.DataFrame): The DataFrame to write.
        """
        df.to_csv(file, index = False)
    
    def auth_action(self, user, target_user):
        """Determines if one user has the authority to perform an action on another user.
        
        Args:
            user (str): The username of the user attempting the action.
            target_user (str): The username of the target user.
        
        Returns:
            bool: True if the action is authorized, otherwise False.
        """
        auth_level_deleter = self.get_auth_level(user)
        auth_level_deletee = self.get_auth_level(target_user)
        return auth_level_deleter <= auth_level_deletee
    
    def check_blocked_user(self, user, user_to_block):
        """Checks if a user can be blocked based on authorization levels.
        
        Args:
            user (str): The username of the user attempting to block.
            user_to_block (str): The username of the user to be blocked.
        
        Returns:
            int: Status code representing the result of the check (1 for blockable, 0 for permission denied, 2 for user does not exist).
        """
        input_df = self.read_csv_as_df()
        if self.entry_exists(user_to_block, input_df):
            if self.auth_action(user, user_to_block):
                return 1 # can block user
            else:
                return 0 # cannot block user (permission denied)
        else:
            return 2 # user_to_block doesn't exist

    def delete_user(self, user, target_user):
        """Deletes a user from the database if authorized.
        
        Args:
            user (str): The username of the user attempting the deletion.
            target_user (str): The username of the user to be deleted.
        
        Returns:
            int: Status code representing the result of the deletion (1 for successful, 0 for permission denied, 2 for user does not exist).
        """
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
        """Deletes the user who is currently logged in from the database.
        
        Args:
            username (str): The username of the logged-in user.
        
        Returns:
            bool: True if the deletion was successful, otherwise False.
        """
        input_df = self.read_csv_as_df()
        removed_user_df = input_df[input_df['username'] != username]
        print("removed user")
        # update csv with user removed
        self.df_to_csv("userinfo.csv", removed_user_df)
        return True
    
    def send_email_and_return_pin(self, email_to_verify):
        """Sends a verification email to a user and returns the verification PIN.
        
        Args:
            email_to_verify (str): The email address to which the verification email is sent.
        
        Returns:
            str: The PIN sent to the user.
        """
        pin = self.generate_pin()
        self.send_ver_email(email_to_verify, pin)
        return pin
    
    def verify_pin(self, pin_to_verify, pin):
        """Verifies if the entered PIN matches the sent PIN.
        
        Args:
            pin_to_verify (str): The PIN entered by the user.
            pin (str): The PIN sent to the user.
        
        Returns:
            bool: True if the PINs match, otherwise False.
        """
        while (True):
            if pin_to_verify is None:
                break
            if pin_to_verify == pin:
                return True
            else:
                return False
        return None

    def generate_pin(self, length=6):
        """Generates a random PIN of specified length.
        
        Args:
            length (int): The length of the PIN to generate.
        
        Returns:
            str: A randomly generated PIN.
        """
        return ''.join(random.choices(string.digits, k=length))
    
    def is_valid_email(self, email):
        """Validates an email address.
        
        Args:
            email (str): The email address to validate.
        
        Returns:
            bool: True if the email is valid, otherwise False.
        """
        try:
            # validate and get info
            valid = validate_email(email)
            email = valid.email
            return True
        except EmailNotValidError as e:
            # email is not valid, exception message is human-readable
            return False

    def send_ver_email(self,recipient_email,pin):
        """Sends a verification email to a user.
        
        Args:
            recipient_email (str): The email address of the recipient.
            pin (str): The verification PIN to include in the email.
        """
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


    def update_pw(self, target_user, password, role):
        """Updates the password for a user in the database.
        
        Args:
            target_user (str): The username of the user whose password is to be updated.
            password (str): The new password for the user.
            role (int): The role of the user to maintain consistency.
        
        Returns:
            None: The user's password is updated in the database.
        """
        input_df = self.read_csv_as_df()

        user_row = input_df[input_df['username'] == target_user]
        user_id = user_row['userID'].iloc[0]

        # Removing the user
        removed_user_df = input_df[input_df['username'] != target_user]

        # Update the CSV without the removed user
        self.df_to_csv("userinfo.csv", removed_user_df)

        # Salt and hash the new password
        salt = self.gen_salt()
        salted_password = password + salt
        hash_obj = hashlib.sha256()
        hash_obj.update(salted_password.encode())
        hex_hashed_password = hash_obj.hexdigest()

        # Add new entry with the updated password
        new_user_info = {
            "username": target_user, 
            "userID": user_id, 
            "role": role,
            "password": hex_hashed_password,
            "salt": salt,
            "verified": True
        }
        self.add_csv_record("userinfo.csv", new_user_info)
