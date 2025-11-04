"""
Lab 6 — Digital Signature (RSA Verify Primitive)

Tasks:
- Given Public Modulus N (hex) and Public Exponent e=0x10001, and a signature
  as a list of hex bytes, compute m = s^e mod N and display ASCII if possible.
"""

def hex_list_to_int():
    print("Enter signature hex bytes separated by spaces (e.g., 0xc8 0x93 ...):")
    parts=input().strip().split()
    hex_pairs=[p[2:].zfill(2) if p.lower().startswith("0x") else p.zfill(2) for p in parts]
    concat="".join(hex_pairs)
    return int(concat,16)

def rsa_verify_recover_message():
    modulus_hex=input("Enter modulus N (hex): ").strip()
    e_hex=input("Enter exponent e (hex), default 10001: ").strip() or "10001"
    sig_int=hex_list_to_int()
    n=int(modulus_hex,16); e=int(e_hex,16)
    m=pow(sig_int,e,n)
    b=m.to_bytes((m.bit_length()+7)//8,'big')
    try:
        print("Recovered ASCII:", b.decode(errors="ignore"))
    except:
        print("Recovered bytes:", b)

if __name__=="__main__":
    print("=== LAB 6 DEMO ===")
    rsa_verify_recover_message()
