import socket

# DJB2 hash function
def djb2_hash(s: str) -> int:
    h = 5381
    for char in s:
        h = ((h << 5) + h) + ord(char)
        h &= 0xFFFFFFFF
    return h

def server_program():
    host = "127.0.0.1"   # localhost
    port = 65432

    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(1)
    print("Server listening...")

    conn, addr = server_socket.accept()
    print(f"Connection from: {addr}")

    # Receive data from client
    data = conn.recv(1024).decode()
    print(f"Received data: {data}")

    # Compute hash
    hash_val = djb2_hash(data)
    print(f"Computed hash: {hash_val}")

    # Send hash back to client
    conn.send(str(hash_val).encode())

    conn.close()

if __name__ == "__main__":
    server_program()