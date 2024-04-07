from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
from base64 import b64encode, b64decode
import json
import base64
import os


class EncryptDecrypt:
    def __init__(self, keys_filename="rsa_keys.json", public_keys="rsa_public.json"):
        self.keys_filename = keys_filename
        self.public_keys = public_keys
        
    def generate_rsa_keys(self, user):
        # Generate RSA keys
        a_key = RSA.generate(2048)
        a_private_key = a_key.export_key().decode('utf-8')
        a_public_key = a_key.publickey().export_key().decode('utf-8')
        
        # Load existing keys from JSON file, if it exists
        try:
            with open(self.keys_filename, 'r') as file:
                keys_data = json.load(file)
        except FileNotFoundError:
            keys_data = {}
        
        # Update keys data with the new keys
        keys_data[user] = {
            "private_key": a_private_key,
        }
        
        # Load existing keys from JSON file, if it exists
        try:
            with open(self.public_keys, 'r') as file:
                keys_data_public = json.load(file)
        except FileNotFoundError:
            keys_data_public = {}
        
        # Update keys data with the new keys
        keys_data_public[user] = {
            "public_key": a_public_key,
        }
        
        # Save the updated keys data back to the JSON file
        with open(self.keys_filename, 'w') as file:
            json.dump(keys_data, file, indent=4)
        
        # Save the updated keys data back to the JSON file
        with open(self.public_keys, 'w') as file:
            json.dump(keys_data_public, file, indent=4)
            
            
    def load_rsa_public_key(self, user):
        # Load the RSA keys data from the JSON file
        with open(self.public_keys, 'r') as file:
            keys_data = json.load(file)
        
        # Extract the specified RSA key for the user
        key_data = keys_data[user]["public_key"].encode('utf-8')
        return RSA.import_key(key_data)
    
    
    def load_rsa_private_key(self, user):
        # Load the RSA keys data from the JSON file
        with open(self.keys_filename, 'r') as file:
            keys_data = json.load(file)
        
        # Extract the specified RSA key for the user
        key_data = keys_data[user]["private_key"].encode('utf-8')
        return RSA.import_key(key_data)


    def aes_encrypt(self, data_bytes, recipient_user, aes_key):
        # Load the recipient's public RSA key
        recipient_public_key = self.load_rsa_public_key(recipient_user)
        
        # Encrypt the data with AES-GCM
        cipher_aes = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data_bytes)
        
        # Encrypt the AES key with the recipient's RSA public key
        cipher_rsa = PKCS1_OAEP.new(recipient_public_key, hashAlgo=SHA256)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        
        concatenated = base64.b64encode(ciphertext) + b":" + \
                   base64.b64encode(tag) + b":" + \
                   base64.b64encode(encrypted_aes_key) + b":" + \
                   base64.b64encode(cipher_aes.nonce)
             
        # Prefix the concatenated data with its length (in 4 bytes)
        concatenated_length = len(concatenated)
        length_prefix = concatenated_length.to_bytes(4, byteorder='big')
        
        return length_prefix + concatenated


    def aes_decrypt(self, encrypted_data, user):
        # Split the encrypted data by the delimiter
        parts = encrypted_data.split(b':')
        print(len(parts))
        if len(parts) != 4:
            raise ValueError("Invalid encrypted data format")
        
        encrypted_message, tag, encrypted_aes_key, nonce = parts

        # Load the user's private RSA key
        user_private_key = self.load_rsa_private_key(user)

        # Decrypt the AES key
        cipher_rsa = PKCS1_OAEP.new(user_private_key, hashAlgo=SHA256)
        aes_key = cipher_rsa.decrypt(base64.b64decode(encrypted_aes_key))
        
        # Decrypt the data with AES-GCM
        cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=base64.b64decode(nonce))
        decrypted_data = cipher_aes.decrypt_and_verify(base64.b64decode(encrypted_message), base64.b64decode(tag))
        
        return decrypted_data

    
class SessionManager:
    def __init__(self):
        self.sessions = {}

    @staticmethod
    def generate_session_id(num_bytes=16):
        return base64.urlsafe_b64encode(os.urandom(num_bytes)).decode('utf-8')
    
    @staticmethod
    def generate_aes_key():
        aes_key = get_random_bytes(32)  # 32 bytes * 8 = 256 bits
        
        return base64.urlsafe_b64encode(aes_key).decode('utf-8')

    def create_session(self, username, recipient):
        # Use a sorted tuple to ensure that the order of usernames does not matter
        user_pair = tuple(sorted((username, recipient)))
        
        # Initialize variable for storing an existing session ID, if found
        existing_session_id = None

        # Iterate over the sessions to check if a session already exists for this user pair
        for key, value in self.sessions.items():
            if value['user'] == user_pair:
                existing_session_id = key
                break  # Exit the loop once a matching session is found

        # If a session already exists for this user pair, return its session ID
        if existing_session_id is not None:
            return existing_session_id

        # If no session exists, generate a new one
        session_id = self.generate_session_id()
        aes_key = self.generate_aes_key()
        self.sessions[session_id] = {
            "user": user_pair,
            "aes_key": aes_key
        }
        return session_id

    def delete_session(self, session_id):
        if session_id in self.sessions:
            del self.sessions[session_id]

    def get_session(self, session_id):
        return self.sessions.get(session_id, None)
    
    def delete_session_username(self, username):
        # Initialize a list to hold the session IDs of sessions to be deleted
        sessions_to_delete = []

        # Iterate over all sessions to find those involving the specified username
        for session_id, session_info in self.sessions.items():
            # Check if the recipient is part of the session
            if username in session_info["user"]:
                sessions_to_delete.append(session_id)
        
        # Delete the identified sessions
        for session_id in sessions_to_delete:
            del self.sessions[session_id]
            
    
