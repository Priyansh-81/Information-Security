# paillier_demo.py
# Requires: pip install sympy pycryptodome
import random
import math
from sympy import randprime

def lcm(a,b): return a*b//math.gcd(a,b)

def generate_paillier_keypair(bits=512):
    # generate two primes p,q
    p = randprime(2**(bits-1), 2**bits)
    q = randprime(2**(bits-1), 2**bits)
    while p==q:
        q = randprime(2**(bits-1), 2**bits)
    n = p*q
    nsq = n*n
    lam = lcm(p-1, q-1)
    # choose g = n+1 (common choice) which simplifies L function
    g = n + 1
    # mu = (L(g^lambda mod n^2))^{-1} mod n
    def L(u): return (u-1)//n
    x = pow(g, lam, nsq)
    mu = pow(L(x), -1, n)
    pub = (n, g)
    priv = (lam, mu)
    return pub, priv

def paillier_encrypt(pub, m):
    n, g = pub
    nsq = n*n
    # choose random r in [1, n-1], gcd(r,n)=1
    while True:
        r = random.randrange(1, n)
        if math.gcd(r, n) == 1:
            break
    c = (pow(g, m, nsq) * pow(r, n, nsq)) % nsq
    return c

def paillier_decrypt(pub, priv, c):
    n, g = pub
    lam, mu = priv
    nsq = n*n
    def L(u): return (u-1)//n
    x = pow(c, lam, nsq)
    m = (L(x) * mu) % n
    return m

if __name__ == "__main__":
    pub, priv = generate_paillier_keypair(bits=256)  # small for demo
    a, b = 15, 25
    ca = paillier_encrypt(pub, a)
    cb = paillier_encrypt(pub, b)
    print("Ciphertext a:", ca)
    print("Ciphertext b:", cb)
    # Homomorphic addition: c_sum = ca * cb mod n^2
    n = pub[0]
    nsq = n*n
    csum = (ca * cb) % nsq
    decrypted_sum = paillier_decrypt(pub, priv, csum)
    print("Decrypted sum:", decrypted_sum)  # should be 40