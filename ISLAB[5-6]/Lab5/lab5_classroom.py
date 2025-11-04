"""
Lab 5 — Hashing & Integrity

Tasks:
1) Implement a simple 32-bit hash (start 5381, h = h*33 + ord(c), with light mixing).
2) TCP hash demo: server computes hash and client verifies.
3) Benchmark MD5/SHA-1/SHA-256 on random strings (time + collision count).
"""

import socket, threading, random, string, time, hashlib

def simple_hash(s: str) -> int:
    h=5381
    for ch in s:
        h = ((h<<5) + h) + ord(ch)  # h*33 + ch
        h ^= (h >> 13)
        h &= 0xFFFFFFFF
    return h

def hash_server(host="127.0.0.1", port=9099):
    srv=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind((host,port)); srv.listen(1)
    print(f"[Server] Listening on {host}:{port}")
    conn,addr=srv.accept()
    data=b""
    while True:
        chunk=conn.recv(4096)
        if not chunk: break
        data+=chunk
    h=simple_hash(data.decode())
    conn.sendall(str(h).encode())
    conn.close(); srv.close()
    print("[Server] Done.")

def start_server():
    th=threading.Thread(target=hash_server, daemon=True)
    th.start()
    return th

def client_send_and_verify(msg: str, host="127.0.0.1", port=9099):
    c=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.connect((host,port))
    c.sendall(msg.encode()); c.shutdown(socket.SHUT_WR)
    srv_hash=int(c.recv(4096).decode()); c.close()
    my_hash=simple_hash(msg)
    print("[Client] Server hash:", srv_hash, "| Local hash:", my_hash, "| Match?", srv_hash==my_hash)

def bench_hashes(samples=100, minlen=8, maxlen=64):
    A=string.ascii_letters+string.digits
    data=[''.join(random.choice(A) for _ in range(random.randint(minlen,maxlen))) for __ in range(samples)]
    for name,fn in (("md5",hashlib.md5),("sha1",hashlib.sha1),("sha256",hashlib.sha256)):
        t0=time.time(); seen=set(); collisions=0
        for s in data:
            d=fn(s.encode()).hexdigest()
            if d in seen: collisions+=1
            seen.add(d)
        print(f"{name.upper():7s}  time={time.time()-t0:.4f}s  digests={len(seen)}  collisions={collisions}")

if __name__=="__main__":
    print("=== LAB 5 DEMO ===")
    th=start_server()
    time.sleep(0.2)
    client_send_and_verify("hello world")
    bench_hashes()
