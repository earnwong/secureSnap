from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
from base64 import b64encode, b64decode


class EncryptDecrypt:
    delimiter = b'<<DELIMITER>>'
    
    def __init__(self):
        pass
    
    def generate_hmac_key():
        hmac_key = get_random_bytes(16)
        with open("h_key.bin", "wb") as file:
            file.write(hmac_key)

    def generate_rsa_keys(self, user):

        a_key = RSA.generate(2048)

        a_private_key = a_key.export_key()
        a_public_key = a_key.publickey().export_key()
        
        bob_key = RSA.generate(2048)

        b_private_key = bob_key.export_key()
        b_public_key = bob_key.publickey().export_key()
        
        with open("a_private_key.pem", "wb") as prv_file:
            prv_file.write(a_private_key)
            
        with open("b_private_key.pem", "wb") as prv_file:
            prv_file.write(b_private_key)
            
        with open("a_public_key.pem", "wb") as prv_file:
            prv_file.write(a_public_key)

        with open("b_public_key.pem", "wb") as prv_file:
            prv_file.write(b_public_key)

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
    
obj = EncryptDecrypt()

def select_photo(self):
    # file_path = easygui.fileopenbox(msg="Select a file to send", title="Select File")
    file_path = "1707446656213.jpg"
    
    if file_path:
        with open(file_path, 'rb') as file:
            while True:
                chunk = file.read(1024)  # Read the file in chunks of 1024 bytes
                if not chunk:
                    break  # If no more data, stop the loop
                
                obj.enc_then_mac
                self.client_socket.sendall(chunk)  # Send the chunk immediately
            # print("File sent successfully.")
    else:
        print("No file selected.")
            
    
