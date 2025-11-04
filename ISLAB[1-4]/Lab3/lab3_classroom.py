"""
Lab 3 — Asymmetric Ciphers

Tasks:
1) RSA: Encrypt/Decrypt "Asymmetric Encryption".
2) ElGamal (mod p): Encrypt/Decrypt "Confidential Data".
3) Diffie–Hellman key exchange: derive shared secret.
(Small, educational parameters — not secure.)
"""

import random, math

# ----- Helpers -----
def egcd(a,b):
    if b==0: return a,1,0
    g,x1,y1=egcd(b,a%b)
    return g,y1,x1-(a//b)*y1

def inv(a,m):
    a%=m
    g,x,_=egcd(a,m)
    if g!=1: raise ValueError("No inverse")
    return x%m

def is_probable_prime(n,k=8):
    if n<2: return False
    small=[2,3,5,7,11,13,17,19,23,29]
    for p in small:
        if n%p==0: return n==p
    d=n-1; s=0
    while d%2==0: d//=2; s+=1
    for _ in range(k):
        a=random.randrange(2,n-2)
        x=pow(a,d,n)
        if x in (1,n-1): continue
        for __ in range(s-1):
            x=pow(x,2,n)
            if x==n-1: break
        else: return False
    return True

def gen_prime(bits):
    while True:
        n=random.getrandbits(bits)|1|(1<<(bits-1))
        if is_probable_prime(n): return n

# ----- RSA -----
def RSA_Keygen():
    bits = int(input("RSA key bits (e.g., 512 or 1024): "))
    e = 65537
    p=gen_prime(bits//2); q=gen_prime(bits//2)
    n=p*q; phi=(p-1)*(q-1)
    if math.gcd(e,phi)!=1:
        return RSA_Keygen()
    d=inv(e,phi)
    print("Public (n,e) generated. Private d computed.")
    return (n,e),(n,d)

def RSA_Encrypt(pub, msg: str):
    n,e=pub
    m=int.from_bytes(msg.encode(),'big')
    if m>=n:
        print("Message too large for modulus.")
        return 0
    c=pow(m,e,n)
    print("RSA Cipher (int):", c)
    return c

def RSA_Decrypt(priv, c: int):
    n,d=priv
    m=pow(c,d,n)
    pt=m.to_bytes((m.bit_length()+7)//8,'big').decode(errors='ignore')
    print("RSA Plaintext:", pt)
    return pt

# ----- ElGamal mod p -----
def ElGamal_Keygen():
    bits=int(input("ElGamal prime bits (e.g., 256): "))
    p=gen_prime(bits); g=2
    x=random.randrange(2,p-2)  # private
    h=pow(g,x,p)               # public h=g^x
    print("Public (p,g,h) and private x generated.")
    return (p,g,h), x

def ElGamal_Encrypt(pub, msg: str):
    p,g,h=pub
    m=int.from_bytes(msg.encode(),'big') % p
    y=random.randrange(2,p-2)
    c1=pow(g,y,p)
    s=pow(h,y,p)
    c2=(m*s)%p
    print("ElGamal Cipher (c1,c2):", c1, c2)
    return (c1,c2)

def ElGamal_Decrypt(pub, x, c):
    p,g,h=pub
    c1,c2=c
    s=pow(c1,x,p)
    s_inv=inv(s,p)
    m=(c2*s_inv)%p
    pt=m.to_bytes((m.bit_length()+7)//8,'big').decode(errors='ignore')
    print("ElGamal Plaintext:", pt)
    return pt

# ----- Diffie–Hellman -----
def DiffieHellman():
    bits=int(input("DH prime bits (e.g., 256): "))
    p=gen_prime(bits); g=2
    a=random.randrange(2,p-2)
    b=random.randrange(2,p-2)
    A=pow(g,a,p); B=pow(g,b,p)
    s1=pow(B,a,p); s2=pow(A,b,p)
    print("DH Shared equal?", s1==s2)
    print("Shared secret (int):", s1)
    return s1

if __name__=="__main__":
    print("=== LAB 3 DEMO ===")
    pub,priv=RSA_Keygen()
    c=RSA_Encrypt(pub,"Asymmetric Encryption"); RSA_Decrypt(priv,c)
    epub,x=ElGamal_Keygen()
    ec=ElGamal_Encrypt(epub,"Confidential Data"); ElGamal_Decrypt(epub,x,ec)
    DiffieHellman()
