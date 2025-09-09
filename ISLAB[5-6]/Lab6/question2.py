import hashlib, hmac, random

p, g = 2087, 2
a = random.randint(2, p-2)  # Alice private
A = pow(g, a, p)
b = random.randint(2, p-2)  # Bob private
B = pow(g, b, p)

K_A = pow(B, a, p)
K_B = pow(A, b, p)
assert K_A == K_B
print("Shared Key:", K_A)

# Use shared key for HMAC
key = hashlib.sha256(str(K_A).encode()).digest()
msg = b"Hello DH"
tag = hmac.new(key, msg, hashlib.sha256).hexdigest()

print("HMAC:", tag)
print("Verify:", tag == hmac.new(key, msg, hashlib.sha256).hexdigest())