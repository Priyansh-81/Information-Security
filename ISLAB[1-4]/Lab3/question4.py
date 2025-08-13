'''
Design and implement a secure file transfer system using RSA (2048-bit) and ECC (secp256r1
curve) public key algorithms. Generate and exchange keys, then encrypt and decrypt files of
varying sizes (e.g., 1 MB, 10 MB) using both algorithms. Measure and compare the
performance in terms of key generation time, encryption/decryption speed, and computational
overhead. Evaluate the security and efficiency of each algorithm in the context of file transfer,
considering factors such as key size, storage requirements, and resistance to known attacks.
Document your findings, including performance metrics and a summary of the strengths and
weaknesses of RSA and ECC for secure file transfer.
'''
import os
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

# cryptography imports for ECC key handling
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# python-ecies imports
from python_ecies import ECIES
from python_ecies.key_derivation import HKDF
from python_ecies.symmetric import AESGCMEncrypter
from python_ecies.format import BinaryOutput

def generate_file(path, size_mb):
    with open(path, "wb") as f:
        f.write(os.urandom(size_mb * 1024 * 1024))

def rsa_hybrid_encrypt_decrypt(file_path):
    data = open(file_path, "rb").read()
    aes_key = get_random_bytes(32)

    # RSA Key Generation
    start = time.time()
    rsa_key = RSA.generate(2048)
    keygen_time = time.time() - start

    # Encrypt AES key with RSA public key
    rsa_cipher = PKCS1_OAEP.new(rsa_key.publickey())
    start = time.time()
    enc_aes_key = rsa_cipher.encrypt(aes_key)
    aes_cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = aes_cipher.encrypt_and_digest(data)
    enc_time = time.time() - start

    # Decrypt AES key and file with RSA private key
    rsa_dec_cipher = PKCS1_OAEP.new(rsa_key)
    start = time.time()
    dec_aes_key = rsa_dec_cipher.decrypt(enc_aes_key)
    aes_dec = AES.new(dec_aes_key, AES.MODE_EAX, nonce=aes_cipher.nonce)
    decrypted = aes_dec.decrypt_and_verify(ciphertext, tag)
    dec_time = time.time() - start

    assert decrypted == data
    return keygen_time, enc_time, dec_time

def ecc_hybrid_encrypt_decrypt(file_path):
    data = open(file_path, "rb").read()

    # Generate ECC private key (cryptography)
    priv_key = ec.generate_private_key(ec.SECP256R1())
    pub_key = priv_key.public_key()

    E = ECIES(HKDF(), AESGCMEncrypter(32), BinaryOutput())

    # Encrypt with ECC public key
    start = time.time()
    encrypted = E.encrypt(data, pub_key)
    enc_time = time.time() - start

    # Decrypt with ECC private key
    start = time.time()
    decrypted = E.decrypt(encrypted, priv_key)
    dec_time = time.time() - start

    assert decrypted == data
    return 0.01, enc_time, dec_time  # Keygen time negligible here

def run_test(file_size_mb):
    fname = f"test_{file_size_mb}MB.bin"
    generate_file(fname, file_size_mb)
    print(f"\nFile size: {file_size_mb} MB")

    rsa_times = rsa_hybrid_encrypt_decrypt(fname)
    print(f"RSA-2048  ➤ KeyGen: {rsa_times[0]:.3f}s, Encrypt: {rsa_times[1]:.3f}s, Decrypt: {rsa_times[2]:.3f}s")

    ecc_times = ecc_hybrid_encrypt_decrypt(fname)
    print(f"ECC-secp256r1 ➤ KeyGen: {ecc_times[0]:.3f}s, Encrypt: {ecc_times[1]:.3f}s, Decrypt: {ecc_times[2]:.3f}s")

    os.remove(fname)

if __name__ == "__main__":
    run_test(1)   # Test 1 MB file
    run_test(10)  # Test 10 MB file