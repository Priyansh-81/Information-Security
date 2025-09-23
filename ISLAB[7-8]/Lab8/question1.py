# sse_demo.py
# pip install pycryptodome
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib

KEY = hashlib.sha256(b"demo-sse-key").digest()[:16]  # 16 bytes AES key for demo

def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC)
    ct = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return cipher.iv, ct

def aes_decrypt(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return pt.decode()

# sample documents
documents = {
    "doc1": "This is a document about cryptography and privacy",
    "doc2": "Another document about networking and security",
    "doc3": "Privacy preserving search is important",
    "doc4": "Homomorphic encryption allows computation on encrypted data",
    "doc5": "Searchable encryption is useful for cloud storage",
    "doc6": "ElGamal and RSA are public key schemes",
    "doc7": "Paillier supports additive homomorphism",
    "doc8": "AES is a symmetric cipher",
    "doc9": "Document retrieval and indexing techniques",
    "doc10":"Network intrusion detection uses signatures"
}

# build inverted index (word -> [docIDs])
from collections import defaultdict
index = defaultdict(list)
for doc_id, text in documents.items():
    words = [w.strip(".,").lower() for w in text.split()]
    for w in set(words):
        index[w].append(doc_id)

# encrypt index: we use deterministic tag = sha256(word) (so equality works)
encrypted_index = {}
for word, doc_list in index.items():
    tag = hashlib.sha256(word.encode()).digest()  # deterministic
    # store encrypted docIDs
    enc_doc_ids = []
    for doc_id in doc_list:
        iv, ct = aes_encrypt(KEY, doc_id)
        enc_doc_ids.append((iv, ct))
    encrypted_index[tag] = enc_doc_ids

# encrypt documents (store iv + ciphertext)
encrypted_documents = {}
for doc_id, text in documents.items():
    iv, ct = aes_encrypt(KEY, text)
    encrypted_documents[doc_id] = (iv, ct)

# search function
def sse_search(query):
    tag = hashlib.sha256(query.lower().encode()).digest()
    if tag not in encrypted_index:
        return []
    enc_doc_ids = encrypted_index[tag]
    out = []
    for iv, ct in enc_doc_ids:
        doc_id = aes_decrypt(KEY, iv, ct)
        doc_iv, doc_ct = encrypted_documents[doc_id]
        doc_text = aes_decrypt(KEY, doc_iv, doc_ct)
        out.append((doc_id, doc_text))
    return out

if __name__ == "__main__":
    q="document"
    results = sse_search(q)
    print(f"Search results for '{q}':")
    for did, text in results:
        print(did, "->", text)