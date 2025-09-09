import hashlib, random
from math import gcd

def H(msg):  # hash to integer
    return int(hashlib.sha256(msg).hexdigest(), 16)

def modinv(a, m):
    if gcd(a, m) != 1: return None
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3:
        q = u3 // v3
        u1, u2, u3, v1, v2, v3 = v1, v2, v3, u1 - q*v1, u2 - q*v2, u3 - q*v3
    return u1 % m

# Parameters (small example)
p, g = 2087, 2
x = random.randint(1, p-2)   # private key
y = pow(g, x, p)             # public key

def sign(msg):
    m = H(msg)
    while True:
        k = random.randint(2, p-2)
        if gcd(k, p-1) == 1:
            break
    r = pow(g, k, p)
    s = (modinv(k, p-1) * (m - x*r)) % (p-1)
    return (r, s)

def verify(msg, sig):
    m = H(msg); r, s = sig
    return pow(g, m, p) == (pow(y, r, p) * pow(r, s, p)) % p

msg = b"ElGamal Demo"
sig = sign(msg)
print("Signature:", sig)
print("Verified:", verify(msg, sig))