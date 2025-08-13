'''
As part of a project to enhance the security of communication in a peer-to-peer file sharing
system, you are tasked with implementing a secure key exchange mechanism using the Diffie
Hellman algorithm. Each peer must establish a shared secret key with another peer over an
insecure channel. Implement the Diffie-Hellman key exchange protocol, enabling peers to
generate their public and private keys and securely compute the shared secret key. Measure
the time taken for key generation and key exchange processes.
'''

import time
import random

def power(a, b, p):
    return pow(a, b, p)

P = 23
G = 9
print(f"Public parameters: P = {P}, G = {G}")

start_keygen_A = time.time()
a = random.randint(2, P - 2)
x = power(G, a, P)
end_keygen_A = time.time()

start_keygen_B = time.time()
b = random.randint(2, P - 2)
y = power(G, b, P)
end_keygen_B = time.time()

start_exchange = time.time()
ka = power(y, a, P)
kb = power(x, b, P)
end_exchange = time.time()

print(f"\nPeer A private key: {a}, public key: {x}")
print(f"Peer B private key: {b}, public key: {y}")
print(f"Shared secret (A): {ka}")
print(f"Shared secret (B): {kb}")
print(f"\nKeys match: {ka == kb}")

print(f"\nKey Generation Time:")
print(f"Peer A: {end_keygen_A - start_keygen_A:.6f} seconds")
print(f"Peer B: {end_keygen_B - start_keygen_B:.6f} seconds")

print(f"\nKey Exchange Time:")
print(f"Exchange & Shared Secret Computation: {end_exchange - start_exchange:.6f} seconds")