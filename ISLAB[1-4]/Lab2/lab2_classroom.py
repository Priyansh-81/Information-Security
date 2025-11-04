"""
Lab 2 — Advanced Symmetric Ciphers

Tasks:
1) DES: Encrypt/Decrypt "Confidential Data" with key "A1B2C3D4".
2) AES-128: Encrypt/Decrypt "Sensitive Information" with key
   "0123456789ABCDEF0123456789ABCDEF".
3) Compare time for DES vs AES-256 on "Performance Testing of Encryption Algorithms".
4) 3DES: Encrypt/Decrypt "Classified Text" with a 24-byte hex key (48 hex chars).
5) AES-192: Encrypt "Top Secret Data" and demonstrate round operations (at a high level).
(Note: Requires PyCryptodome. If not installed, follow: pip install pycryptodome)
"""

import binascii, time

try:
    from Crypto.Cipher import DES, DES3, AES
    from Crypto.Util.Padding import pad, unpad
except Exception:
    DES = DES3 = AES = None
    def pad(b, bs): 
        padlen = bs - (len(b) % bs)
        return b + bytes([padlen])*padlen
    def unpad(b, bs):
        return b[:-b[-1]]

def hex_to_bytes(h: str, size: int | None = None) -> bytes:
    b = binascii.unhexlify(h.encode())
    if size is None: return b
    return (b + b"\x00"*size)[:size]

def DES_ECB_Encrypt():
    if DES is None:
        print("DES not available. Install pycryptodome.")
        return b""
    key_hex = input("Enter DES key as hex (e.g., A1B2C3D4): ")
    msg = input('Enter message (default "Confidential Data"): ') or "Confidential Data"
    key = hex_to_bytes(key_hex, 8)
    c = DES.new(key, DES.MODE_ECB)
    ct = c.encrypt(pad(msg.encode(), 8))
    print("Cipher (hex):", binascii.hexlify(ct).decode())
    return ct, key

def DES_ECB_Decrypt(ct=None, key=None):
    if DES is None:
        print("DES not available. Install pycryptodome.")
        return
    if ct is None:
        ct_hex = input("Enter DES ciphertext hex: ")
        ct = binascii.unhexlify(ct_hex.encode())
        key_hex = input("Enter DES key hex: ")
        key = hex_to_bytes(key_hex, 8)
    c = DES.new(key, DES.MODE_ECB)
    pt = unpad(c.decrypt(ct), 8).decode()
    print("Decrypted:", pt)
    return pt

def AES_Encrypt(bits=128):
    if AES is None:
        print("AES not available. Install pycryptodome.")
        return b"", b""
    key_hex = input(f"Enter AES-{bits} key hex: ")
    msg = input('Enter message (default "Sensitive Information"): ') or "Sensitive Information"
    key = hex_to_bytes(key_hex, bits//8)
    c = AES.new(key, AES.MODE_ECB)
    ct = c.encrypt(pad(msg.encode(), 16))
    print("Cipher (hex):", binascii.hexlify(ct).decode())
    return ct, key

def AES_Decrypt(ct=None, key=None):
    if AES is None:
        print("AES not available. Install pycryptodome.")
        return
    if ct is None:
        ct_hex = input("Enter AES ciphertext hex: ")
        ct = binascii.unhexlify(ct_hex.encode())
        bits = int(input("Enter key size in bits (128/192/256): "))
        key_hex = input(f"Enter AES-{bits} key hex: ")
        key = hex_to_bytes(key_hex, bits//8)
    c = AES.new(key, AES.MODE_ECB)
    pt = unpad(c.decrypt(ct), 16).decode(errors="ignore")
    print("Decrypted:", pt)
    return pt

def TripleDES_ECB_Encrypt():
    if DES3 is None:
        print("3DES not available. Install pycryptodome.")
        return b"", b""
    key_hex = input("Enter 3DES 48-hex-char key: ")
    msg = input('Enter message (default "Classified Text"): ') or "Classified Text"
    raw = hex_to_bytes(key_hex)
    key = DES3.adjust_key_parity(raw[:24])
    c = DES3.new(key, DES3.MODE_ECB)
    ct = c.encrypt(pad(msg.encode(), 8))
    print("Cipher (hex):", binascii.hexlify(ct).decode())
    return ct, key

def TripleDES_ECB_Decrypt(ct=None, key=None):
    if DES3 is None:
        print("3DES not available. Install pycryptodome.")
        return
    if ct is None:
        ct_hex = input("Enter 3DES ciphertext hex: ")
        ct = binascii.unhexlify(ct_hex.encode())
        key_hex = input("Enter 3DES key hex (48 hex chars): ")
        raw = hex_to_bytes(key_hex)
        key = DES3.adjust_key_parity(raw[:24])
    c = DES3.new(key, DES3.MODE_ECB)
    pt = unpad(c.decrypt(ct), 8).decode()
    print("Decrypted:", pt)
    return pt

def Compare_DES_vs_AES256():
    if DES is None or AES is None:
        print("Install pycryptodome to run timing.")
        return
    msg = "Performance Testing of Encryption Algorithms"
    # DES
    t0 = time.time()
    des_ct, des_key = DES_ECB_Encrypt()
    DES_ECB_Decrypt(des_ct, des_key)
    t1 = time.time()
    # AES-256
    print("\nNow AES-256:")
    ct, key = AES_Encrypt(256)
    AES_Decrypt(ct, key)
    t2 = time.time()
    print(f"\nDES total time: {t1 - t0:.6f}s")
    print(f"AES-256 total time: {t2 - t1:.6f}s")

if __name__ == "__main__":
    print("=== LAB 2 DEMO ===")
    ct,k = DES_ECB_Encrypt(); DES_ECB_Decrypt(ct,k)
    ct,k = AES_Encrypt(128); AES_Decrypt(ct,k)
    ct,k = TripleDES_ECB_Encrypt(); TripleDES_ECB_Decrypt(ct,k)
    Compare_DES_vs_AES256()
