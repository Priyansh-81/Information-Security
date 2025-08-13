'''
Given an ElGamal encryption scheme with a public key (p, g, h) and a private key x, encrypt
the message "Confidential Data". Then decrypt the ciphertext to retrieve the original message.
'''

import random
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

p = getPrime(256)
g = random.randint(2, p - 1)
x = random.randint(2, p - 2)
h = pow(g, x, p)

message = b"Confidential Data"
m = bytes_to_long(message)

y = random.randint(2, p - 2)
c1 = pow(g, y, p)
s = pow(h, y, p)
c2 = (m * s) % p

ciphertext = (c1, c2)
print("Message Encrypted:", ciphertext)

s_dec = pow(c1, x, p)
s_inv = pow(s_dec, -1, p)
m_dec = (c2 * s_inv) % p
decrypted_message = long_to_bytes(m_dec)

print("Message Decrypted:", decrypted_message.decode())
