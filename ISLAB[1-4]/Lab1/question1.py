'''
1. Encrypt the message "I am learning information security" using one of the following ciphers.
Ignore the space between words. Decrypt the message to get the original plaintext:
a) Additive cipher with key = 20
b) Multiplicative cipher with key = 15
c) Affine cipher with key = (15, 20)
'''
def CeaserEncrypt(text):
    key = int(input("Enter the key for additive cipher: "))
    plaintext = text.replace(" ", "").upper()
    ciphertext = ""
    for ch in plaintext:
        if ch.isalpha():
            shift = (ord(ch) - ord('A') + key) % 26
            ciphertext += chr(shift + ord('A'))
        else:
            ciphertext += ch
    print("Original plaintext: " + text + "\nAdditive Ciphertext: " + ciphertext)
    return ciphertext

def CeaserDecrypt(text):
    key = int(input("Enter the key for additive cipher: "))
    ciphertext = text.upper()
    plaintext = ""
    for ch in ciphertext:
        if ch.isalpha():
            shift = (ord(ch) - ord('A') - key) % 26
            plaintext += chr(shift + ord('A'))
        else:
            plaintext += ch
    print("Additive Ciphertext: " + text + "\nDecrypted Plaintext: " + plaintext)

def multiplicativeEncrypt(text):
    key = int(input("Enter the key for multiplicative cipher: "))
    plaintext = text.replace(" ", "").upper()
    ciphertext = ""
    for ch in plaintext:
        if ch.isalpha():
            shift = ((ord(ch) - ord('A')) * key) % 26
            ciphertext += chr(shift + ord('A'))
        else:
            ciphertext += ch
    print("Original plaintext: " + text + "\nMultiplicative Ciphertext: " + ciphertext)
    return ciphertext

def multiplicativeDecrypt(text):
    key = int(input("Enter the key for multiplicative cipher: "))
    # Find modular inverse of key modulo 26
    def mod_inverse(a, m):
        for i in range(1, m):
            if (a * i) % m == 1:
                return i
        return None

    inverse_key = mod_inverse(key, 26)
    if inverse_key is None:
        print("No modular inverse exists for key =", key)
        return

    ciphertext = text.upper()
    plaintext = ""
    for ch in ciphertext:
        if ch.isalpha():
            shift = ((ord(ch) - ord('A')) * inverse_key) % 26
            plaintext += chr(shift + ord('A'))
        else:
            plaintext += ch
    print("Multiplicative Ciphertext: " + text + "\nDecrypted Plaintext: " + plaintext)

def affineEncrypt(text):
    a = int(input("Enter multiplicative key (a): "))
    b = int(input("Enter additive key (b): "))
    plaintext = text.replace(" ", "").upper()
    ciphertext = ""
    for ch in plaintext:
        if ch.isalpha():
            shift = ((ord(ch) - ord('A')) * a + b) % 26
            ciphertext += chr(shift + ord('A'))
        else:
            ciphertext += ch
    print("Original plaintext: " + text + "\nAffine Ciphertext: " + ciphertext)
    return ciphertext

def affineDecrypt(text):
    a = int(input("Enter multiplicative key (a): "))
    b = int(input("Enter additive key (b): "))
    def mod_inverse(a, m):
        for i in range(1, m):
            if (a * i) % m == 1:
                return i
        return None

    a_inv = mod_inverse(a, 26)
    if a_inv is None:
        print("No modular inverse exists for key =", a)
        return

    ciphertext = text.upper()
    plaintext = ""
    for ch in ciphertext:
        if ch.isalpha():
            shift = ((ord(ch) - ord('A') - b) * a_inv) % 26
            plaintext += chr(shift + ord('A'))
        else:
            plaintext += ch
    print("Affine Ciphertext: " + text + "\nDecrypted Plaintext: " + plaintext)

plaintext = "I am learning information security"
cipher1 = CeaserEncrypt(plaintext)
CeaserDecrypt(cipher1)

cipher2 = multiplicativeEncrypt(plaintext)
multiplicativeDecrypt(cipher2)

cipher3 = affineEncrypt(plaintext)
affineDecrypt(cipher3)
