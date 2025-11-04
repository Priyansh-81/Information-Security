"""
Lab 4 — KMS Client
Connects to the server and sends commands interactively.
"""

import socket

def send_command(cmd):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 9090))
    s.sendall(cmd.encode())
    s.shutdown(socket.SHUT_WR)
    print(s.recv(8192).decode())
    s.close()

if __name__ == "__main__":
    print("Connected to KMS server (localhost:9090)")
    while True:
        cmd = input("Enter command (REGISTER/LIST/REVOKE/EXIT): ").strip()
        if cmd.upper() == "EXIT":
            break
        send_command(cmd)