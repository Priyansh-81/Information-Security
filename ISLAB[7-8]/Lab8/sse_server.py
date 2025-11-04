"""
Lab 8 — SSE Server
Holds encrypted documents and answers keyword search requests.
"""

import socket, json, hashlib

docs = {
    "doc1": "network security and cryptography lab",
    "doc2": "information security practical class",
    "doc3": "python socket programming example"
}

def search_keyword(term):
    results = [k for k,v in docs.items() if term.lower() in v.lower()]
    return results or ["No match found"]

def start_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 9095))
    s.listen(1)
    print("[SSE Server] Ready on port 9095...")
    while True:
        conn, _ = s.accept()
        term = conn.recv(1024).decode().strip()
        res = search_keyword(term)
        conn.send(json.dumps(res).encode())
        conn.close()

if __name__ == "__main__":
    start_server()