"""
Lab 4 — Key Management & Advanced Asymmetric

Tasks:
• Provide a simple Key Management System (KMS) to register entities,
  store RSA/Rabin keys, rotate, revoke and log events.
• Show small demos for RSA and Rabin (educational).

NOTE: This is a simple file-based simulator suitable for class demos.
"""

import json, os, time, random, math, secrets

STORE = "kms_store.json"

def _load():
    if not os.path.exists(STORE):
        return {"entities":{}, "revoked":[], "logs":[]}
    with open(STORE,"r",encoding="utf-8") as f: return json.load(f)

def _save(db):
    with open(STORE,"w",encoding="utf-8") as f: json.dump(db,f,indent=2)

def log(event, **meta):
    db=_load()
    db["logs"].append({"ts":time.time(),"event":event,"meta":meta})
    _save(db)

# --- Math helpers ---
def egcd(a,b):
    if b==0: return a,1,0
    g,x1,y1=egcd(b,a%b)
    return g,y1,x1-(a//b)*y1

def inv(a,m):
    a%=m
    g,x,_=egcd(a,m)
    if g!=1: raise ValueError("no inverse")
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
        n=secrets.randbits(bits)|1|(1<<(bits-1))
        if is_probable_prime(n): return n

# --- RSA & Rabin ---
def rsa_keygen(bits=1024, e=65537):
    p=gen_prime(bits//2); q=gen_prime(bits//2)
    n=p*q; phi=(p-1)*(q-1); d=inv(e,phi)
    return {"n":n,"e":e,"d":d}

def rabin_keygen(bits=1024):
    def p3mod4(b):
        while True:
            q=gen_prime(b)
            if q%4==3: return q
    p=p3mod4(bits//2); q=p3mod4(bits//2)
    return {"p":p,"q":q,"n":p*q}

# --- KMS APIs ---
def kms_register():
    name=input("Entity name: ")
    algo=input("Algorithm (RSA/RABIN): ").upper()
    bits=int(input("Key bits (e.g., 1024): "))
    keys = rsa_keygen(bits) if algo=="RSA" else rabin_keygen(bits)
    db=_load()
    db["entities"][name]={"algo":algo,"keys":keys,"created":time.time(),"expires":time.time()+365*24*3600}
    _save(db); log("register", entity=name, algo=algo)
    print("Registered:", name)

def kms_rotate():
    name=input("Entity to rotate: ")
    db=_load()
    ent=db["entities"].get(name)
    if not ent: print("Unknown entity"); return
    algo=ent["algo"]
    bits=int(input("New key bits (e.g., 1024): "))
    ent["keys"] = rsa_keygen(bits) if algo=="RSA" else rabin_keygen(bits)
    ent["expires"] = time.time()+365*24*3600
    _save(db); log("rotate", entity=name)
    print("Rotated:", name)

def kms_revoke():
    name=input("Entity to revoke: ")
    reason=input("Reason: ")
    db=_load()
    if name in db["entities"]:
        db["revoked"].append({"name":name,"reason":reason,"ts":time.time()})
        _save(db); log("revoke", entity=name, reason=reason)
        print("Revoked:", name)
    else:
        print("Unknown entity")

def kms_list():
    db=_load()
    print(json.dumps(db, indent=2))

if __name__=="__main__":
    print("=== LAB 4 KMS DEMO ===")
    while True:
        print("\n1) Register  2) Rotate  3) Revoke  4) List  5) Exit")
        ch=input("Choice: ").strip()
        if ch=="1": kms_register()
        elif ch=="2": kms_rotate()
        elif ch=="3": kms_revoke()
        elif ch=="4": kms_list()
        else: break
