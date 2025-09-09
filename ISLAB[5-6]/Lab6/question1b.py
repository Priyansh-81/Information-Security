import hashlib, random

def H(*parts):
    h = hashlib.sha256()
    for p in parts:
        if isinstance(p, int):
            p = p.to_bytes((p.bit_length()+7)//8 or 1, 'big')
        h.update(p)
    return int(h.hexdigest(), 16)

# Parameters (toy)
q = 1019
p = 2*q + 1
g = 2
x = random.randint(1, q-1)     # private key
y = pow(g, x, p)               # public key

def sign(msg):
    k = random.randint(1, q-1)
    r = pow(g, k, p)
    e = H(r, msg) % q
    s = (k + x*e) % q
    return (e, s)

def verify(msg, sig):
    e, s = sig
    v = (pow(g, s, p) * pow(y, -e, p)) % p
    return e == H(v, msg) % q

msg = b"Schnorr Demo"
sig = sign(msg)
print("Signature:", sig)
print("Verified:", verify(msg, sig))