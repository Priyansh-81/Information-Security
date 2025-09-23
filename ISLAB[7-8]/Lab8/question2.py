# pkse_paillier_demo.py
# pip install sympy pycryptodome
import hashlib, random, math
from sympy import randprime

def lcm(a,b): return a*b//math.gcd(a,b)

def generate_paillier_keypair(bits=256):
    p = randprime(2**(bits-1), 2**bits)
    q = randprime(2**(bits-1), 2**bits)
    while p==q: q = randprime(2**(bits-1), 2**bits)
    n = p*q
    nsq = n*n
    lam = lcm(p-1, q-1)
    g = n+1
    def L(u): return (u-1)//n
    mu = pow(L(pow(g, lam, nsq)), -1, n)
    return (n, g), (lam, mu)

def paillier_encrypt_with_r(pub, m, r):
    n, g = pub
    nsq = n*n
    return (pow(g, m, nsq) * pow(r, n, nsq)) % nsq

def paillier_encrypt(pub, m):
    n, g = pub
    nsq = n*n
    while True:
        r = random.randrange(1, n)
        if math.gcd(r, n) == 1:
            break
    return paillier_encrypt_with_r(pub, m, r)

def paillier_decrypt(pub, priv, c):
    n, g = pub
    lam, mu = priv
    nsq = n*n
    def L(u): return (u-1)//n
    x = pow(c, lam, nsq)
    return (L(x) * mu) % n

# sample docs (same as SSE demo)
documents = {
 "doc1": "this is a document about cryptography and privacy",
 "doc2": "another document about networking and security",
 "doc3": "privacy preserving search is important",
 "doc4": "homomorphic encryption allows computation on encrypted data",
 "doc5": "searchable encryption is useful for cloud storage",
 "doc6": "elgamal and rsa are public key schemes",
 "doc7": "paillier supports additive homomorphism",
 "doc8": "aes is a symmetric cipher",
 "doc9": "document retrieval and indexing techniques",
 "doc10":"network intrusion detection uses signatures"
}

# Build inverted index
from collections import defaultdict
index = defaultdict(list)
for doc_id, text in documents.items():
    words = [w.strip(".,").lower() for w in text.split()]
    for w in set(words):
        index[w].append(doc_id)

pub, priv = generate_paillier_keypair(bits=256)  # small bits for demo

# For demonstration: deterministic word tag by hashing to int and encrypting with fixed r per word.
encrypted_index = {}
for word, doc_list in index.items():
    # deterministic integer tag:
    whash = hashlib.sha256(word.encode()).digest()
    m = int.from_bytes(whash[:8], "big")
    # choose deterministic r derived from whash (INSECURE — demo only)
    r = int.from_bytes(whash[8:16], "big") % pub[0]
    if r == 0: r = 1
    ctag = paillier_encrypt_with_r(pub, m, r)
    # encrypt docIDs (here we encrypt docID integers deterministically too)
    enc_doc_ids = []
    for did in doc_list:
        dnum = int(did.replace("doc",""))
        # deterministic r for doc encryption
        rdoc = (r + dnum) % pub[0]
        if rdoc == 0: rdoc = 1
        cdoc = paillier_encrypt_with_r(pub, dnum, rdoc)
        enc_doc_ids.append(cdoc)
    encrypted_index[ctag] = enc_doc_ids

# Search: compute tag for query and look up
def pkse_search(query):
    whash = hashlib.sha256(query.encode()).digest()
    m = int.from_bytes(whash[:8], "big")
    r = int.from_bytes(whash[8:16], "big") % pub[0]
    if r == 0: r = 1
    ctag = paillier_encrypt_with_r(pub, m, r)
    if ctag not in encrypted_index:
        return []
    enc_doc_ids = encrypted_index[ctag]
    doc_ids = []
    for cdoc in enc_doc_ids:
        dnum = paillier_decrypt(pub, priv, cdoc)
        doc_ids.append(f"doc{dnum}")
    return doc_ids

if __name__ == "__main__":
    print("Search for 'document' ->", pkse_search("document"))