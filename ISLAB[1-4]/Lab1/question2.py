'''
 Encrypt the message "the house is being sold tonight" using one of the following ciphers.
Ignore the space between words. Decrypt the message to get the original plaintext:
• Vigenere cipher with key: "dollars"
• Autokey cipher with key = 7
'''
def AutokeyEncrypt(plaintext, key):
    plaintext = plaintext.replace(" ", "").upper()
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    key_letter = alphabet[key % 26]
    keystream = key_letter + plaintext
    ciphertext = ""

    for i in range(len(plaintext)):
        p = alphabet.index(plaintext[i])
        k = alphabet.index(keystream[i])
        c = (p + k) % 26
        ciphertext += alphabet[c]
    return ciphertext

def AutokeyDecrypt(ciphertext, key):
    ciphertext = ciphertext.upper()
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    key_letter = alphabet[key % 26]
    keystream = key_letter
    plaintext = ""

    for i in range(len(ciphertext)):
        c = alphabet.index(ciphertext[i])
        k = alphabet.index(keystream[i])
        p = (c - k + 26) % 26
        plain_char = alphabet[p]
        plaintext += plain_char
        keystream += plain_char
    return plaintext

def VigenereEncrypt(plaintext, key):
    plaintext = plaintext.replace(" ", "").upper()
    key = key.upper()
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ciphertext = ""

    key_stream = (key * ((len(plaintext) // len(key)) + 1))[:len(plaintext)]

    for p, k in zip(plaintext, key_stream):
        p_index = alphabet.index(p)
        k_index = alphabet.index(k)
        c_index = (p_index + k_index) % 26
        ciphertext += alphabet[c_index]
    return ciphertext

def VigenereDecrypt(ciphertext, key):
    ciphertext = ciphertext.upper()
    key = key.upper()
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    plaintext = ""

    key_stream = (key * ((len(ciphertext) // len(key)) + 1))[:len(ciphertext)]

    for c, k in zip(ciphertext, key_stream):
        c_index = alphabet.index(c)
        k_index = alphabet.index(k)
        p_index = (c_index - k_index + 26) % 26
        plaintext += alphabet[p_index]
    return plaintext

plaintext = "the house is being sold tonight"
print("Vignere Cipher\n")
print("Plaintext:", plaintext)
key=input("Enter the key:")
ciphertext = VigenereEncrypt(plaintext, key)
print("Vigenere Ciphertext:", ciphertext)
decrypted = VigenereDecrypt(ciphertext, key)
print("Decrypted text:", decrypted)
plaintext = "the house is being sold tonight"
key = int(input("Enter the numeric key for Autokey cipher (e.g., 7): "))
ciphertext = AutokeyEncrypt(plaintext, key)
print("Plaintext:", plaintext)
print("Ciphertext:", ciphertext)
decrypted = AutokeyDecrypt(ciphertext, key)
print("Decrypted text:", decrypted)
