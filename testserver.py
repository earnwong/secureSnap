import socket
import threading

clients = {"bob": None, "samantha": None}  # Dictionary to store client usernames and connections

def client_handler(connection):
    try:
        # Receive the login username from the client
        username = connection.recv(1024).decode()
        if not username:
            return
        clients[username] = connection
        print(f"{username} logged in.")

        while True:
            # Wait for data from the client
            data = connection.recv(1024).decode()
            if not data:
                break  # Connection closed

            recipient, message = data.split(':', 1)
            if recipient in clients:
                clients[recipient].sendall(f"From {username}: {message}".encode())
            else:
                connection.sendall("Recipient not found.".encode())
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        connection.close()
        clients.pop(username, None)  # Remove the client from the list

def start_server():
    host = 'localhost'
    port = 6000

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('', port))
    server_socket.listen()
    print(f"Server listening on port {port}")

    while True:
        client_socket, _ = server_socket.accept()
        thread = threading.Thread(target=client_handler, args=(client_socket,))
        thread.start()

if __name__ == "__main__":
    start_server()
