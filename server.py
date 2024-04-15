import sys
import socket
from os import _exit as quit
import threading
from encrypt import SessionManager, EncryptDecrypt
import base64
from Crypto.Cipher import PKCS1_OAEP
import json
import threading

clients = {}  # store the connfd
logged_in = {} # Keeps track of who logged in

session_manager = SessionManager()
encryptdecrypt = EncryptDecrypt()

lock = threading.Lock()




def send_aes_key_to_client(session_id, client_public_key):
    aes_key_b64 = session_manager.get_session(session_id)['aes_key']
    aes_key = base64.urlsafe_b64decode(aes_key_b64.encode('utf-8'))

    # Encrypt the AES key with the client's public RSA key
    cipher_rsa = PKCS1_OAEP.new(client_public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    return encrypted_aes_key

def receive_length_prefixed_data(sock):
        # First, read the length of the data (4 bytes)
        print("hanging here")
        length_bytes = sock.recv(4)
        print("length bytes:", length_bytes)
        if not length_bytes:
            raise ConnectionError("Server: Failed to receive data length prefix")
        data_length = int.from_bytes(length_bytes, byteorder='big')
        # print(data_length)
        
        # Read the specified amount of data
        data = b''
        while len(data) < data_length:
            remaining_bytes = data_length - len(data)
            data += sock.recv(remaining_bytes)
        
        return (data_length, length_bytes + data)       


def client_handler(connfd):
    try:
        # Receive the login username from the client
        username = connfd.recv(1024).decode()
        # if username in clients:
        clients[username] = connfd
        logged_in[username] = 'yes'
        print(f"{username} logged in.")
        connfd.sendall("You have successfully logged in".encode())
        # else:
        #     connfd.sendall("Wrong username".encode())
        #     return
        
        
        while True:
            recipient = connfd.recv(1024).decode()
            if recipient == "END_SESSION":
                session_manager.delete_session_username(username)
                print("Session ended by the client.")
                break

            if recipient == "send":
                # Convert the dictionary to a JSON string
                logged_in_json = json.dumps(logged_in)

                # Encode the JSON string to bytes
                logged_in_bytes = logged_in_json.encode('utf-8')
                #send list of available users
                print("Length of data to be sent:", len(logged_in_json))
                connfd.sendall(logged_in_bytes)
                continue
                
            if (recipient in clients) and logged_in[recipient] == 'yes':
                print("this works")
                userIsAvailable = len("This user is available".encode('utf-8'))
                print("USER IS AVAIL LENGTH: ", userIsAvailable)
                connfd.sendall("This user is available".encode('utf-8'))
                print("PART 2")
                
                # generate session id
                session_id = session_manager.create_session(username, recipient)
                
                # get the public key
                client_public_key = encryptdecrypt.load_rsa_public_key(username)
                
                # send the encrypted aes key to the user so they can encrypt their message
                AES_KEY = send_aes_key_to_client(session_id, client_public_key)
                print("AES key len: ", len(AES_KEY))
                
                connfd.sendall(AES_KEY)
            
                print("this stuff also works")
                #clients[recipient].sendall("photo available".encode('utf-8'))
                while True:
                    len_data, data = receive_length_prefixed_data(connfd)
                    if (len_data < 1763):
                        clients[recipient].sendall(data)
                        print("no more data")
                        sys.stdout.flush()
                        break  # No more data to receive
                    clients[recipient].sendall(data)
        
                
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        print(f'{username} logged out')
        connfd.close()
        del clients[username]
        session_manager.delete_session_username(username)
        del logged_in[username]

        
def main():
    # parse arguments
    if len(sys.argv) != 2:
        print("usage: python3 %s <port>" % sys.argv[0])
        quit(1)
    port = sys.argv[1]
    # config = sys.argv[2]
    
    # open a socket
    listenfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listenfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # bind socket to ip and port
    listenfd.bind(('', int(port)))

    # listen to socket
    listenfd.listen(5)

    # accept connection
    while True:
        (connfd, addr) = listenfd.accept()
        thread = threading.Thread(target=client_handler, args=(connfd,))
        thread.start()
    



    # close connection
    connfd.close()
    listenfd.close()


if __name__ == "__main__":
    main()


