"""
Lab 8 — Searchable Encryption (SSE + PKSE-like demo)

Tasks:
1) Build an encrypted inverted index over small documents (SSE: AES + SHA-256 tokens).
   Query with a search term to retrieve matching doc IDs.
2) PKSE-like variant: Protect posting-list entries with Paillier; decrypt results for display.
(These are simplified, demo-level implementations for learning.)
"""

import json, hashlib, secrets, random, math

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except Exception:
    AES=None
    def pad(b,bs): padlen=bs-(len(b)%bs); return b+bytes([padlen])*padlen
    def unpad(b,bs): return b[:-b[-1]]

# ---- SSE ----
def sse_key(): return secrets.token_bytes(16)
def sse_token(term: str) -> bytes: return hashlib.sha256(term.lower().encode()).digest()

def sse_encrypt(key: bytes, data: bytes):
    if AES is None: return b"\x00"*16, pad(data,16)
    c=AES.new(key,AES.MODE_CBC)
    return c.iv, c.encrypt(pad(data,16))

def sse_decrypt(key: bytes, iv: bytes, ct: bytes) -> bytes:
    if AES is None: return unpad(ct,16)
    c=AES.new(key,AES.MODE_CBC,iv)
    return unpad(c.decrypt(ct),16)

def sse_build_index(docs: dict[str,str], key: bytes):
    inv={}
    for doc_id, text in docs.items():
        for w in text.split():
            inv.setdefault(sse_token(w), []).append(doc_id)
    enc_index={}
    for tok, ids in inv.items():
        tiv,tct=sse_encrypt(key,tok)
        div,dct=sse_encrypt(key,json.dumps(ids).encode())
        enc_index[(tiv,tct)]=(div,dct)
    return enc_index

def sse_search(enc_index, key: bytes, query: str):
    tok=sse_token(query)
    tiv,tct=sse_encrypt(key,tok)
    for (iv1,ct1),(iv2,ct2) in enc_index.items():
        if iv1==tiv and ct1==tct:
            return json.loads(sse_decrypt(key,iv2,ct2).decode())
    return []

# ---- Paillier (for PKSE-like payloads) ----
def paillier_keygen(bits=256):
    def gen_prime(bits):
        while True:
            n=random.getrandbits(bits)|1|(1<<(bits-1))
            if all(n%p for p in [3,5,7,11,13,17,19,23,29]): return n
    p=gen_prime(bits//2); q=gen_prime(bits//2)
    n=p*q; lam=(p-1)*(q-1)//math.gcd(p-1,q-1)
    g=n+1; mu=pow((pow(g,lam,n*n)-1)//n, -1, n)
    return (n,g),(lam,mu)

def pai_enc(m:int, pub):
    n,g=pub
    r=random.randrange(1,n)
    while math.gcd(r,n)!=1: r=random.randrange(1,n)
    return (pow(g,m,n*n)*pow(r,n,n*n))%(n*n)

def pai_dec(c:int, pub, priv):
    n,g=pub; lam,mu=priv
    x=pow(c,lam,n*n); L=(x-1)//n
    return (L*mu)%n

def pkse_build_index(docs: dict[str,str], pub):
    inv={}
    for idx,(doc_id,text) in enumerate(docs.items()):
        for w in text.split():
            h=int.from_bytes(hashlib.sha256(w.lower().encode()).digest(),'big')
            inv.setdefault(h,[]).append(idx)
    enc_index={h:[pai_enc(i,pub) for i in ids] for h,ids in inv.items()}
    return enc_index

def pkse_search(enc_index, pub, priv, query: str):
    h=int.from_bytes(hashlib.sha256(query.lower().encode()).digest(),'big')
    if h not in enc_index: return []
    return [pai_dec(c,pub,priv) for c in enc_index[h]]

if __name__=="__main__":
    print("=== LAB 8 DEMO ===")
    docs={f"doc{i}": f"this is sample document number {i} with topic crypto lab lab{i%3}" for i in range(10)}
    k=sse_key()
    idx=sse_build_index(docs,k)
    print("SSE search 'document' ->", sse_search(idx,k,"document"))

    pub,priv=paillier_keygen(256)
    pidx=pkse_build_index(docs,pub)
    print("PKSE search 'crypto' -> doc indexes", pkse_search(pidx,pub,priv,"crypto"))
