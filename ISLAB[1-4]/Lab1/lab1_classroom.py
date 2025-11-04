"""
Lab 1 — Basic Symmetric Ciphers (Classroom Style)

Tasks:
1) Encrypt "I am learning information security" using:
   a) Additive (key = 20)
   b) Multiplicative (key = 15)
   c) Affine (a=15, b=20)
   Decrypt to recover plaintext (ignore spaces).

2) Encrypt "the house is being sold tonight" using:
   a) Vigenère (key="dollars")
   b) Autokey (seed=7)
   Decrypt both.

3) Playfair: Encipher "The key is hidden under the door pad" with keyword "GUIDANCE".
   (I/J merged; ignore spaces.) Decrypt back.

4) Hill 2x2: Encipher "We live in an insecure world" with K=[[3,3],[2,7]]. Decrypt back.

5) Known-plaintext: "CIW" is shift of "yes". Find attack & decode "XVIEWYWI".

6) Affine brute force with known pair "ab" -> "GL" for ciphertext:
   XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS
"""

# ---------- Helpers ----------
def only_letters_upper(s: str) -> str:
    return "".join(ch for ch in s.upper() if ch.isalpha())

def mod_inverse(a: int, m: int) -> int | None:
    a %= m
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None

# ---------- 1a: Additive (Caesar) ----------
def CaesarEncrypt(text: str) -> str:
    key = int(input("Enter additive key (e.g., 20): "))
    pt = only_letters_upper(text)
    ct = ""
    for ch in pt:
        shift = (ord(ch) - 65 + key) % 26
        ct += chr(65 + shift)
    print("\n[Additive Cipher]")
    print("Plaintext :", text)
    print("Ciphertext:", ct)
    return ct

def CaesarDecrypt(text: str) -> str:
    key = int(input("Enter additive key for decryption: "))
    ct = only_letters_upper(text)
    pt = ""
    for ch in ct:
        shift = (ord(ch) - 65 - key) % 26
        pt += chr(65 + shift)
    print("Decrypted :", pt)
    return pt

# ---------- 1b: Multiplicative ----------
def MultiplicativeEncrypt(text: str) -> str:
    key = int(input("Enter multiplicative key (coprime to 26, e.g., 15): "))
    if math.gcd(key, 26) != 1:
        print("Key must be coprime to 26!")
        return ""
    pt = only_letters_upper(text)
    ct = ""
    for ch in pt:
        val = (ord(ch) - 65)
        shift = (val * key) % 26
        ct += chr(65 + shift)
    print("\n[Multiplicative Cipher]")
    print("Plaintext :", text)
    print("Ciphertext:", ct)
    return ct

def MultiplicativeDecrypt(text: str) -> str:
    key = int(input("Enter multiplicative key for decryption: "))
    inv = mod_inverse(key, 26)
    if inv is None:
        print("No inverse for key modulo 26.")
        return ""
    ct = only_letters_upper(text)
    pt = ""
    for ch in ct:
        val = (ord(ch) - 65)
        shift = (val * inv) % 26
        pt += chr(65 + shift)
    print("Decrypted :", pt)
    return pt

# ---------- 1c: Affine ----------
def AffineEncrypt(text: str) -> str:
    a = int(input("Enter multiplicative key a (coprime to 26): "))
    b = int(input("Enter additive key b: "))
    if math.gcd(a, 26) != 1:
        print("a must be coprime to 26")
        return ""
    pt = only_letters_upper(text)
    ct = ""
    for ch in pt:
        x = ord(ch) - 65
        y = (a * x + b) % 26
        ct += chr(65 + y)
    print("\n[Affine Cipher]")
    print("Plaintext :", text)
    print("Ciphertext:", ct)
    return ct

def AffineDecrypt(text: str) -> str:
    a = int(input("Enter multiplicative key a used in encryption: "))
    b = int(input("Enter additive key b used in encryption: "))
    inv = mod_inverse(a, 26)
    if inv is None:
        print("No inverse for a modulo 26")
        return ""
    ct = only_letters_upper(text)
    pt = ""
    for ch in ct:
        y = ord(ch) - 65
        x = (inv * (y - b)) % 26
        pt += chr(65 + x)
    print("Decrypted :", pt)
    return pt

# ---------- 2a: Vigenère ----------
def VigenereEncrypt(text: str) -> str:
    key = input("Enter Vigenere key (letters): ").upper().replace(" ", "")
    if not key or not key.isalpha():
        print("Invalid key")
        return ""
    pt = only_letters_upper(text)
    ct = ""
    for i, ch in enumerate(pt):
        k = ord(key[i % len(key)]) - 65
        shift = (ord(ch) - 65 + k) % 26
        ct += chr(65 + shift)
    print("\n[Vigenere Cipher]")
    print("Plaintext :", text)
    print("Ciphertext:", ct)
    return ct

def VigenereDecrypt(text: str) -> str:
    key = input("Enter Vigenere key used in encryption: ").upper().replace(" ", "")
    ct = only_letters_upper(text)
    pt = ""
    for i, ch in enumerate(ct):
        k = ord(key[i % len(key)]) - 65
        shift = (ord(ch) - 65 - k) % 26
        pt += chr(65 + shift)
    print("Decrypted :", pt)
    return pt

# ---------- 2b: Autokey (numeric seed) ----------
def AutokeyEncrypt(text: str) -> str:
    seed = int(input("Enter numeric autokey seed (e.g., 7): "))
    pt = only_letters_upper(text)
    shifts = [seed] + [ord(c) - 65 for c in pt[:-1]]
    ct = ""
    for i, ch in enumerate(pt):
        shift = (ord(ch) - 65 + shifts[i]) % 26
        ct += chr(65 + shift)
    print("\n[Autokey Cipher]")
    print("Plaintext :", text)
    print("Ciphertext:", ct)
    return ct

def AutokeyDecrypt(text: str) -> str:
    seed = int(input("Enter numeric autokey seed used in encryption: "))
    ct = only_letters_upper(text)
    pt = ""
    last = seed
    for ch in ct:
        m = (ord(ch) - 65 - last) % 26
        pt += chr(65 + m)
        last = m
    print("Decrypted :", pt)
    return pt

# ---------- 3: Playfair ----------
def PF_build_matrix(keyword: str) -> list[list[str]]:
    keyword = keyword.upper().replace("J", "I")
    seen = []
    for ch in keyword:
        if ch.isalpha() and ch not in seen:
            seen.append(ch)
    for ch in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch not in seen:
            seen.append(ch)
    return [seen[i:i+5] for i in range(0, 25, 5)]

def PF_find(mtx, ch):
    for r in range(5):
        for c in range(5):
            if mtx[r][c] == ch:
                return r, c
    return None

def PF_prepare(text: str) -> str:
    s = only_letters_upper(text).replace("J", "I")
    out = ""
    i = 0
    while i < len(s):
        a = s[i]
        if i + 1 < len(s):
            b = s[i+1]
            if a == b:
                out += a + "X"
                i += 1
            else:
                out += a + b
                i += 2
        else:
            out += a + "X"
            i += 1
    return out

def PlayfairEncrypt(text: str) -> str:
    key = input("Enter Playfair keyword (e.g., GUIDANCE): ")
    M = PF_build_matrix(key)
    pairs = PF_prepare(text)
    ct = ""
    for i in range(0, len(pairs), 2):
        a, b = pairs[i], pairs[i+1]
        r1, c1 = PF_find(M, a)
        r2, c2 = PF_find(M, b)
        if r1 == r2:
            ct += M[r1][(c1+1)%5] + M[r2][(c2+1)%5]
        elif c1 == c2:
            ct += M[(r1+1)%5][c1] + M[(r2+1)%5][c2]
        else:
            ct += M[r1][c2] + M[r2][c1]
    print("\n[Playfair Cipher]\nCiphertext:", ct)
    return ct

def PlayfairDecrypt(text: str) -> str:
    key = input("Enter Playfair keyword used in encryption: ")
    M = PF_build_matrix(key)
    ct = only_letters_upper(text)
    pt = ""
    for i in range(0, len(ct), 2):
        a, b = ct[i], ct[i+1]
        r1, c1 = PF_find(M, a)
        r2, c2 = PF_find(M, b)
        if r1 == r2:
            pt += M[r1][(c1-1)%5] + M[r2][(c2-1)%5]
        elif c1 == c2:
            pt += M[(r1-1)%5][c1] + M[(r2-1)%5][c2]
        else:
            pt += M[r1][c2] + M[r2][c1]
    print("Decrypted :", pt)
    return pt

# ---------- 4: Hill 2x2 ----------
def Hill2Encrypt(text: str) -> str:
    print("Enter 2x2 key matrix values (a b; c d).")
    a = int(input("a: ")); b = int(input("b: "))
    c = int(input("c: ")); d = int(input("d: "))
    pt = only_letters_upper(text)
    if len(pt) % 2 == 1:
        pt += "X"
    ct = ""
    for i in range(0, len(pt), 2):
        x = ord(pt[i]) - 65
        y = ord(pt[i+1]) - 65
        u = (a*x + b*y) % 26
        v = (c*x + d*y) % 26
        ct += chr(65 + u) + chr(65 + v)
    print("\n[Hill 2x2]")
    print("Ciphertext:", ct)
    return ct

def Hill2Decrypt(text: str) -> str:
    print("Enter the SAME 2x2 key matrix used for encryption (a b; c d).")
    a = int(input("a: ")); b = int(input("b: "))
    c = int(input("c: ")); d = int(input("d: "))
    det = (a*d - b*c) % 26
    inv_det = mod_inverse(det, 26)
    if inv_det is None:
        print("Matrix not invertible mod 26.")
        return ""
    Ai = ( d * inv_det) % 26
    Bi = (-b * inv_det) % 26
    Ci = (-c * inv_det) % 26
    Di = ( a * inv_det) % 26
    ct = only_letters_upper(text)
    if len(ct) % 2 == 1:
        print("Invalid ciphertext length for Hill 2x2.")
        return ""
    pt = ""
    for i in range(0, len(ct), 2):
        u = ord(ct[i]) - 65
        v = ord(ct[i+1]) - 65
        x = (Ai*u + Bi*v) % 26
        y = (Ci*u + Di*v) % 26
        pt += chr(65 + x) + chr(65 + y)
    print("Decrypted :", pt)
    return pt

# ---------- 5: Known-plaintext shift ----------
def KnownPlaintextDemo():
    print("\n[Known-Plaintext Shift Attack]")
    cipher_known = "CIW"
    plain_known  = "YES"
    shift = (ord(cipher_known[0]) - ord(plain_known[0])) % 26
    mystery = "XVIEWYWI"
    decoded = ""
    for ch in only_letters_upper(mystery):
        decoded += chr(65 + ((ord(ch) - 65 - shift) % 26))
    print(f"Computed shift: {shift}")
    print("Decoded mystery:", decoded)

# ---------- 6: Affine brute force with one known pair ----------
def AffineBruteForceKnownPair():
    print("\n[Affine Brute Force with Known Pair]")
    ct = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"
    plain_pair = "AB"; cipher_pair = "GL"
    p1, p2 = ord(plain_pair[0]) - 65, ord(plain_pair[1]) - 65
    c1, c2 = ord(cipher_pair[0]) - 65, ord(cipher_pair[1]) - 65
    candidates = []
    for a in range(1, 26):
        if math.gcd(a, 26) != 1: continue
        b = (c1 - a*p1) % 26
        if (a*p2 + b) % 26 != c2: continue
        # decrypt with (a,b)
        inv = mod_inverse(a, 26)
        out = ""
        for ch in only_letters_upper(ct):
            y = ord(ch) - 65
            x = (inv * (y - b)) % 26
            out += chr(65 + x)
        candidates.append((a,b,out))
    if candidates:
        print("Possible (a,b) keys and plaintexts:")
        for a,b,out in candidates:
            print(f"a={a:2d}, b={b:2d} -> {out}")
    else:
        print("No candidates found.")

# ---------------------- DEMO ----------------------
if __name__ == "__main__":
    print("=== LAB 1 DEMO ===")
    p1 = "I am learning information security"
    c1 = CaesarEncrypt(p1); CaesarDecrypt(c1)
    c2 = MultiplicativeEncrypt(p1); MultiplicativeDecrypt(c2)
    c3 = AffineEncrypt(p1); AffineDecrypt(c3)

    p2 = "the house is being sold tonight"
    v = VigenereEncrypt(p2); VigenereDecrypt(v)
    au = AutokeyEncrypt(p2); AutokeyDecrypt(au)

    p3 = "The key is hidden under the door pad"
    pf = PlayfairEncrypt(p3); PlayfairDecrypt(pf)

    # Hill example key [[3,3],[2,7]]
    h = Hill2Encrypt("We live in an insecure world"); Hill2Decrypt(h)

    KnownPlaintextDemo()
    AffineBruteForceKnownPair()
