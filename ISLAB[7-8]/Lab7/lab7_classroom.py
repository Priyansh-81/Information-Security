"""
Lab 7 — Partial Homomorphic Encryption (PHE)

Tasks:
1) Paillier (additive): keygen, encrypt two integers, multiply ciphertexts to add, decrypt.
2) RSA (textbook multiplicative): encrypt a and b, multiply ciphertexts mod n, decrypt to get a*b.
"""

import random, math

def lcm(a,b): return abs(a*b)//math.gcd(a,b)

# ---- Paillier ----
def paillier_keygen(bits=256):
    def gen_prime(bits):
        while True:
            n=random.getrandbits(bits)|1|(1<<(bits-1))
            if all(n%p for p in [3,5,7,11,13,17,19,23,29]): return n
    p=gen_prime(bits//2); q=gen_prime(bits//2)
    n=p*q; lam=lcm(p-1,q-1)
    g=n+1; mu=pow((pow(g,lam,n*n)-1)//n, -1, n)
    return (n,g),(lam,mu)

def paillier_encrypt(m, pub):
    n,g=pub
    r=random.randrange(1,n)
    while math.gcd(r,n)!=1: r=random.randrange(1,n)
    return (pow(g,m,n*n)*pow(r,n,n*n))%(n*n)

def paillier_decrypt(c, pub, priv):
    n,g=pub; lam,mu=priv
    x=pow(c,lam,n*n); L=(x-1)//n
    return (L*mu)%n

def paillier_demo():
    pub,priv=paillier_keygen(256)
    a=int(input("Enter integer a: "))
    b=int(input("Enter integer b: "))
    ca=paillier_encrypt(a,pub); cb=paillier_encrypt(b,pub)
    csum=(ca*cb)%(pub[0]*pub[0])
    dec=paillier_decrypt(csum,pub,priv)
    print("Decrypted (a+b):", dec)

# ---- RSA multiplicative ----
def rsa_keygen(bits=512,e=65537):
    def gen_prime(bits):
        while True:
            n=random.getrandbits(bits)|1|(1<<(bits-1))
            if all(n%p for p in [3,5,7,11,13,17,19,23,29]): return n
    p=gen_prime(bits//2); q=gen_prime(bits//2)
    n=p*q; phi=(p-1)*(q-1); d=pow(e,-1,phi)
    return (n,e),(n,d)

def rsa_enc(m,pub): n,e=pub; return pow(m,e,n)
def rsa_dec(c,priv): n,d=priv; return pow(c,d,n)

def rsa_mult_demo():
    pub,priv=rsa_keygen(512)
    a=int(input("Enter integer a: "))
    b=int(input("Enter integer b: "))
    cprod=(rsa_enc(a,pub)*rsa_enc(b,pub))%pub[0]
    out=rsa_dec(cprod,priv)
    print("Decrypted (a*b mod n):", out, "(Note: equals a*b only if a*b < n)")

if __name__=="__main__":
    print("=== LAB 7 DEMO ===")
    paillier_demo()
    rsa_mult_demo()
