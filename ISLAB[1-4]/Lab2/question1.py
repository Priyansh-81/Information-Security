# Q1: DES encryption/decryption
import sys
print(sys.executable)

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import binascii

pt = "Confidential Data"
key = b"A1B2C3D4"  # 8-byte DES key

# Encrypt
cipher = DES.new(key, DES.MODE_ECB)
ct = cipher.encrypt(pad(pt.encode(), DES.block_size))
print("Ciphertext (hex):", binascii.hexlify(ct).decode())

# Decrypt
decipher = DES.new(key, DES.MODE_ECB)
pt_out = unpad(decipher.decrypt(ct), DES.block_size).decode()
print("Decrypted text:", pt_out)