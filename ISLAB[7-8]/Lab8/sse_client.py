"""
Lab 8 — SSE Client
Sends a keyword to the server and displays matching document IDs.
"""

import socket, json

def start_client():
    while True:
        term = input("Enter search term (or 'exit'): ").strip()
        if term.lower() == "exit":
            break
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 9095))
        s.send(term.encode())
        s.shutdown(socket.SHUT_WR)
        data = s.recv(4096)
        print("Search results:", json.loads(data.decode()))
        s.close()

if __name__ == "__main__":
    start_client()