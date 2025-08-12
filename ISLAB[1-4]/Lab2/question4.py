# Q4: Triple DES encryption/decryption
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import binascii

pt = "Classified Text"
raw_key = b"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
key = DES3.adjust_key_parity(raw_key[:24])  # Ensure valid parity

cipher = DES3.new(key, DES3.MODE_ECB)
ct = cipher.encrypt(pad(pt.encode(), DES3.block_size))
print("Ciphertext (hex):", binascii.hexlify(ct).decode())

decipher = DES3.new(key, DES3.MODE_ECB)
pt_out = unpad(decipher.decrypt(ct), DES3.block_size).decode()
print("Decrypted text:", pt_out)