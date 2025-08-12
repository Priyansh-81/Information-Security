# Q5: AES-192 encryption/decryption
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii

pt = "Top Secret Data"
raw_key = b"FEDCBA9876543210FEDCBA9876543210"
key = raw_key[:24]  # AES-192 = 24-byte key

cipher = AES.new(key, AES.MODE_ECB)
ct = cipher.encrypt(pad(pt.encode(), AES.block_size))
print("Ciphertext (hex):", binascii.hexlify(ct).decode())

decipher = AES.new(key, AES.MODE_ECB)
pt_out = unpad(decipher.decrypt(ct), AES.block_size).decode()
print("Decrypted text:", pt_out)

print("\nAES-192 Process:")
print("1. Key expansion (24-byte key → 12 rounds)")
print("2. Initial round: AddRoundKey")
print("3. 11 main rounds: SubBytes, ShiftRows, MixColumns, AddRoundKey")
print("4. Final round: SubBytes, ShiftRows, AddRoundKey (no MixColumns)")