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
    delimiter = b'<<DELIMITER>>'
    
    def __init__(self):
        pass
        
    def generate_hmac_key():
        hmac_key = get_random_bytes(16)
        with open("h_key.bin", "wb") as file:
            file.write(hmac_key)

    def generate_rsa_keys(self, user1):

        a_key = RSA.generate(2048)

        a_private_key = a_key.export_key()
        a_public_key = a_key.publickey().export_key()
        
        with open(f"{user1}_private_key.pem", "wb") as prv_file:
            prv_file.write(a_private_key)
            
        with open(f"{user1}_public_key.pem", "wb") as prv_file:
            prv_file.write(a_public_key)
            

    def generate_aes_key():
        aes_key = get_random_bytes(32)  # 32 bytes * 8 = 256 bits
        
        with open("aes.enc", "wb") as aes_file:
            aes_file.write(aes_key)
            
    def hmac_generate(msg, enc=False):
        with open("h_key.bin", "rb") as h:
            h_key = h.read()
        secret_key = HMAC.new(h_key, digestmod=SHA256)
        if enc:
            secret_key.update(msg)
        else:
            secret_key.update(msg.encode('utf-8'))
            
        mac = secret_key.digest() # the tag
        
        return msg, mac

    def aes_encrypt(msg):
        b_public_key = RSA.import_key(open("b_public_key.pem").read())
        
        # open the AES key 
        with open("aes.enc", 'rb') as enc_key:
            aes_key = enc_key.read()

        # Encrypt the AES key with the recipient's public RSA key
        cipher_rsa = PKCS1_OAEP.new(b_public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        
        # Create a new AES cipher in CTR mode
        cipher_aes = AES.new(aes_key, AES.MODE_CTR)
        
        # Encrypt the message
        enc_msg = cipher_aes.encrypt(msg.encode('utf-8'))
        
        # Extract the nonce used for encryption
        iv = cipher_aes.nonce
        
        return enc_msg, encrypted_aes_key, iv


    def enc_then_mac(self, msg):
        enc_msg, encrypted_aes_key, iv = self.aes_encrypt(msg)

        enc_msg, mac = self.hmac_generate(enc_msg, enc=True)

        return mac, enc_msg, encrypted_aes_key, iv
    
    def hmac_verify(msg, mac, enc=False):
        with open("h_key.bin", "rb") as h:
            h_key = h.read()
        ver_key = HMAC.new(h_key, digestmod=SHA256)
        if enc: 
            ver_key.update(msg)
        else:
            ver_key.update(msg.encode('utf-8'))
        try:
            ver_key.verify(mac)
            print(f"HMAC verified successfully.")
            return 1
        except ValueError:
            print(f"Failed to verify HMAC! Your message has been tampered with.")
            return 0
        

    def aes_decrypt(enc_msg, enc_aes_key, iv):
        b_private_key = RSA.import_key(open("b_private_key.pem").read())
        
        cipher_rsa = PKCS1_OAEP.new(b_private_key)
        decrypted_aes_key = cipher_rsa.decrypt(enc_aes_key)
        
        # Create a new AES cipher in CTR mode using the decrypted AES key and the nonce
        cipher_aes = AES.new(decrypted_aes_key, AES.MODE_CTR, nonce=iv)
        
        # Decrypt the message
        aes_dec = cipher_aes.decrypt(enc_msg)
            
        return aes_dec.decode('utf-8')

    def enc_then_mac_decrypt(self, mac, enc_msg, enc_aes_key, iv):
        if self.hmac_verify(enc_msg, mac, enc=True):
            return self.aes_decrypt(enc_msg, enc_aes_key, iv)
        else:
            return
    

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
            
    
