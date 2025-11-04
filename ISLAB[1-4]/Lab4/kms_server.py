"""
Lab 4 — KMS Server
Handles key registration, listing, rotation, and revocation.
Stores all data in 'kms_data.json'.
"""

import socket, json, time, threading, os

DATA_FILE = "kms_data.json"

def load_data():
    if not os.path.exists(DATA_FILE):
        return {"entities": {}}
    with open(DATA_FILE, "r") as f:
        return json.load(f)

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)

def handle_client(conn):
    data = conn.recv(4096).decode().strip()
    if not data:
        conn.close()
        return
    parts = data.split()
    cmd = parts[0].upper()
    db = load_data()

    if cmd == "REGISTER":
        if len(parts) < 3:
            conn.send(b"Usage: REGISTER <Name> <Algorithm>\n")
        else:
            name, algo = parts[1], parts[2]
            db["entities"][name] = {"algo": algo, "created": time.ctime()}
            save_data(db)
            conn.send(f"Entity '{name}' registered with {algo}\n".encode())

    elif cmd == "LIST":
        conn.send(json.dumps(db, indent=2).encode())

    elif cmd == "REVOKE":
        if len(parts) < 2:
            conn.send(b"Usage: REVOKE <Name>\n")
        else:
            name = parts[1]
            if name in db["entities"]:
                del db["entities"][name]
                save_data(db)
                conn.send(f"Entity '{name}' revoked.\n".encode())
            else:
                conn.send(b"Entity not found.\n")

    else:
        conn.send(b"Unknown command.\n")
    conn.close()

def start_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 9090))
    srv.listen(5)
    print("[KMS Server] Running on port 9090...")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_client, args=(conn,), daemon=True).start()

if __name__ == "__main__":
    start_server()