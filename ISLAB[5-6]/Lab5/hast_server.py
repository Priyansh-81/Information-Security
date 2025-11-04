"""
Lab 5 — Hash Server
Receives text, computes simple hash, and sends it back.
"""

import socket

def simple_hash(s: str) -> int:
    h = 5381
    for ch in s:
        h = ((h << 5) + h) + ord(ch)
        h ^= (h >> 13)
        h &= 0xFFFFFFFF
    return h

def start_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 9099))
    s.listen(1)
    print("[Server] Listening on port 9099...")
    conn, _ = s.accept()
    data = conn.recv(4096).decode()
    h = simple_hash(data)
    conn.send(str(h).encode())
    conn.close()
    s.close()
    print("[Server] Hash sent:", h)

if __name__ == "__main__":
    start_server()