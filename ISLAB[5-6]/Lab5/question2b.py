import socket

# DJB2 hash function
def djb2_hash(s: str) -> int:
    h = 5381
    for char in s:
        h = ((h << 5) + h) + ord(char)
        h &= 0xFFFFFFFF
    return h

def client_program():
    host = "127.0.0.1"
    port = 65432

    client_socket = socket.socket()
    client_socket.connect((host, port))

    # Data to send
    message = "Hello Server"
    print(f"Sending data: {message}")

    client_socket.send(message.encode())

    # Receive hash from server
    server_hash = int(client_socket.recv(1024).decode())
    print(f"Received hash from server: {server_hash}")

    # Locally compute hash
    local_hash = djb2_hash(message)
    print(f"Locally computed hash: {local_hash}")

    # Integrity check
    if server_hash == local_hash:
        print("✅ Data integrity verified. No corruption.")
    else:
        print("❌ Data corrupted or tampered during transmission!")

    client_socket.close()

if __name__ == "__main__":
    client_program()