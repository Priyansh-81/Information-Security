'''
Using RSA, encrypt the message "Asymmetric Encryption" with the public key (n, e). Then
decrypt the ciphertext with the private key (n, d) to verify the original message.
'''
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

key=RSA.generate(2048)
private=key.exportKey()
public=key.publickey().exportKey()

msg=b'Asymmetric Encryption'
public_key_obj=RSA.importKey(public)
cipher=PKCS1_OAEP.new(public_key_obj)
ct=cipher.encrypt(msg)

print(f"Message encrypted: {ct}")
private_key_obj=RSA.importKey(private)
decipher=PKCS1_OAEP.new(private_key_obj)
pt=decipher.decrypt(ct)
print(f"Message decrypted: {pt}")
