import sys
import socket
from os import _exit as quit
# from Crypto.PublicKey import RSA
# from Crypto.Cipher import AES, PKCS1_OAEP
# from Crypto.Hash import HMAC, SHA256
# from dashboard import Dashboard
import threading

clients = {"bob": None, "samantha": None, "cathy": None}  # Dummy dictionary to store client usernames and connections

def client_handler(connfd):
    try:
        # Receive the login username from the client
        username = connfd.recv(1024).decode()
        if username in clients:
            clients[username] = connfd
            print(f"{username} logged in.")
            connfd.sendall("You have successfully logged in".encode())
        else:
            connfd.sendall("Wrong username".encode())
            return

        while True:
            recipient = connfd.recv(1024).decode()
            if recipient == "END_SESSION":
                print("Session ended by the client.")
                break

            if recipient in clients:
                connfd.sendall("This user is available".encode())

                while True:
                    data = connfd.recv(1024)  # Receive data in chunks
                    #print(len(data))
                    #print(data[-1])
                    
                    if (len(data) < 1024):
                        clients[recipient].sendall(data)
                        print("no more data")
                        sys.stdout.flush()
                        break  # No more data to receive
                    clients[recipient].sendall(data)
                    #print("Sending data.....")
                clients[recipient].sendall(b"END_OF_FILE") # small bug here we have to fix

                    
            else:
                connfd.sendall("Recipient not found".encode())
        
                
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        connfd.close()
        clients[username] = None  # Remove the client from the list 
    
        
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
    
    
    # # message loop
    # while(True):
        




    # close connection
    connfd.close()
    listenfd.close()


if __name__ == "__main__":
    main()


