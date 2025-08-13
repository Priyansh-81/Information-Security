'''
Using ECC (Elliptic Curve Cryptography), encrypt the message "Secure Transactions" with
the public key. Then decrypt the ciphertext with the private key to verify the original message.
'''
from ecies.utils import generate_key
from ecies import encrypt, decrypt


private_key = generate_key()
public_key = private_key.public_key

message = b"Secure Transactions"
ciphertext = encrypt(public_key.format(True), message)
print("Message Encrypted:", ciphertext)

decrypted_message = decrypt(private_key.to_hex(), ciphertext)
print("Message Decrypted:", decrypted_message.decode())