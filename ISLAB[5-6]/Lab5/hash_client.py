"""
Lab 5 — Hash Client
Sends text to the server and verifies the returned hash.
"""

import socket

def simple_hash(s: str) -> int:
    h = 5381
    for ch in s:
        h = ((h << 5) + h) + ord(ch)
        h ^= (h >> 13)
        h &= 0xFFFFFFFF
    return h

def start_client():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 9099))
    msg = input("Enter message to hash: ")
    s.send(msg.encode())
    s.shutdown(socket.SHUT_WR)
    srv_hash = int(s.recv(1024).decode())
    local_hash = simple_hash(msg)
    print(f"Server hash: {srv_hash}\nLocal hash : {local_hash}")
    print("Match?", srv_hash == local_hash)
    s.close()

if __name__ == "__main__":
    start_client()