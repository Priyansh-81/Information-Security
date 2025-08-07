import numpy as np
from sympy import Matrix

def mod_inverse_matrix(matrix, modulus):
    sympy_matrix = Matrix(matrix)
    return np.array(sympy_matrix.inv_mod(modulus)).astype(int)

def hill_encrypt(plaintext, key_matrix):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    plaintext = plaintext.replace(" ", "").upper()

    # Pad with 'X' if length is odd
    if len(plaintext) % 2 != 0:
        plaintext += 'X'

    ciphertext = ""
    for i in range(0, len(plaintext), 2):
        pair = plaintext[i:i+2]
        vector = np.array([[alphabet.index(pair[0])], [alphabet.index(pair[1])]])
        result = np.dot(key_matrix, vector) % 26
        ciphertext += alphabet[result[0][0]] + alphabet[result[1][0]]
    return ciphertext

def hill_decrypt(ciphertext, key_matrix):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ciphertext = ciphertext.upper()

    inverse_key = mod_inverse_matrix(key_matrix, 26)

    plaintext = ""
    for i in range(0, len(ciphertext), 2):
        pair = ciphertext[i:i+2]
        vector = np.array([[alphabet.index(pair[0])], [alphabet.index(pair[1])]])
        result = np.dot(inverse_key, vector) % 26
        plaintext += alphabet[result[0][0]] + alphabet[result[1][0]]
    return plaintext

key_matrix = np.array([[3, 3], [2, 7]])

plaintext = "We live in an insecure world"

ciphertext = hill_encrypt(plaintext, key_matrix)
print("Ciphertext:", ciphertext)

decrypted = hill_decrypt(ciphertext, key_matrix)
print("Decrypted:", decrypted)
