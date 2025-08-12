# Q2: AES-128 encryption/decryption
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii

pt = "Sensitive Information"
raw_key = b"0123456789ABCDEF0123456789ABCDEF"
key = raw_key[:16]  # AES-128 = 16-byte key

cipher = AES.new(key, AES.MODE_ECB)
ct = cipher.encrypt(pad(pt.encode(), AES.block_size))
print("Ciphertext (hex):", binascii.hexlify(ct).decode())

decipher = AES.new(key, AES.MODE_ECB)
pt_out = unpad(decipher.decrypt(ct), AES.block_size).decode()
print("Decrypted text:", pt_out)