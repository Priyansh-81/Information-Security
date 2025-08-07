'''
 Use the Playfair cipher to encipher the message "The key is hidden under the door pad". The
secret key can be made by filling the first and part of the second row with the word
"GUIDANCE" and filling the rest of the matrix with the rest of the alphabet.
'''

import numpy as np
import string


def create_playfair_matrix_np(key):
    key = key.upper().replace('J', 'I')
    used = set()

    letters = []
    for char in key:
        if char.isalpha() and char not in used:
            used.add(char)
            letters.append(char)

    for char in string.ascii_uppercase:
        if char == 'J':
            continue
        if char not in used:
            used.add(char)
            letters.append(char)

    matrix = np.array(letters).reshape((5, 5))
    return matrix


def preprocess_text(text):
    text = text.upper().replace('J', 'I')
    text = ''.join(filter(str.isalpha, text))

    digraphs = []
    i = 0
    while i < len(text):
        a = text[i]
        b = ''
        if i + 1 < len(text):
            b = text[i + 1]
        else:
            b = 'X'
        if a == b:
            digraphs.append(a + 'X')
            i += 1
        else:
            digraphs.append(a + b)
            i += 2
    return digraphs


def find_position_np(matrix, char):
    pos = np.where(matrix == char)
    return pos[0][0], pos[1][0]  # row, col


def playfair_encrypt_digraph_np(matrix, digraph):
    a, b = digraph[0], digraph[1]
    r1, c1 = find_position_np(matrix, a)
    r2, c2 = find_position_np(matrix, b)
    if r1 == r2:
        c1 = (c1 + 1) % 5
        c2 = (c2 + 1) % 5
    elif c1 == c2:
        r1 = (r1 + 1) % 5
        r2 = (r2 + 1) % 5
    else:
        c1, c2 = c2, c1
    return matrix[r1, c1] + matrix[r2, c2]


def playfair_encrypt_np(matrix, digraphs):
    ciphertext = ''.join(playfair_encrypt_digraph_np(matrix, dg) for dg in digraphs)
    return ciphertext


key = "GUIDANCE"
plaintext = "The key is hidden under the door pad"

matrix = create_playfair_matrix_np(key)
print("Playfair Key Matrix:\n", matrix)

digraphs = preprocess_text(plaintext)
print("Prepared digraphs:", digraphs)

ciphertext = playfair_encrypt_np(matrix, digraphs)
print("Ciphertext:", ciphertext)
