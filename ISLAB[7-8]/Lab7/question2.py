# rsa_mul_demo.py
from sympy import randprime
import random
import math

def generate_rsa_keypair(bits=256):
    p = randprime(2**(bits-1), 2**bits)
    q = randprime(2**(bits-1), 2**bits)
    while p==q:
        q = randprime(2**(bits-1), 2**bits)
    n = p*q
    phi = (p-1)*(q-1)
    e = 65537
    # ensure gcd(e,phi)=1
    if math.gcd(e, phi) != 1:
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2
    d = pow(e, -1, phi)
    pub = (n, e)
    priv = (n, d)
    return pub, priv

def rsa_encrypt(pub, m):
    n, e = pub
    return pow(m, e, n)

def rsa_decrypt(priv, c):
    n, d = priv
    return pow(c, d, n)

if __name__ == "__main__":
    pub, priv = generate_rsa_keypair(bits=256)
    a, b = 7, 3
    ca = rsa_encrypt(pub, a)
    cb = rsa_encrypt(pub, b)
    print("ciphertext a:", ca)
    print("ciphertext b:", cb)
    # multiplicative homomorphism:
    cmul = (ca * cb) % pub[0]
    decrypted = rsa_decrypt(priv, cmul)
    print("Decrypted product (mod n):", decrypted)  # should equal 21 mod n