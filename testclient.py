import socket

def connect_to_server(host, port, username):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((host, port))
    server_socket.sendall(username.encode())  # Send the username right after connecting
    return server_socket

def send_message(server_socket, recipient, message):
    server_socket.sendall(f"{recipient}:{message}".encode())
    response = server_socket.recv(1024).decode()
    print(f"Server response: {response}")

if __name__ == "__main__":
    host = 'localhost'
    port = 6000
    username = input("Enter your username: ")
    server_socket = connect_to_server(host, port, username)

    try:
        recipient = input("Enter recipient username: ")
        message = input("Enter your message: ")
        send_message(server_socket, recipient, message)
    finally:
        server_socket.close()
