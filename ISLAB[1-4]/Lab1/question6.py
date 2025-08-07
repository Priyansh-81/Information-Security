'''
Use a brute-force attack to decipher the following message. Assume that you know it is an
affine cipher and that the plaintext "ab" is enciphered to "GL":
XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS
'''

'''
here we can see a-> G, and b->L, and it says that it uses affine cipher, again its a known plaintext attack

'''

def affineEncrypt():
    text="AB"
    a = int(input("Enter multiplicative key (a): "))
    b = int(input("Enter additive key (b): "))
    plaintext = text.replace(" ", "").upper()
    ciphertext = ""
    for ch in plaintext:
        if ch.isalpha():
            shift = ((ord(ch) - ord('A')) * a + b) % 26
            ciphertext += chr(shift + ord('A'))
        else:
            ciphertext += ch
    print("Original plaintext: " + text + "\nAffine Ciphertext: " + ciphertext)
    return ciphertext

def affineDecrypt():
    text="XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"
    a = int(input("Enter multiplicative key (a): "))
    b = int(input("Enter additive key (b): "))
    def mod_inverse(a, m):
        for i in range(1, m):
            if (a * i) % m == 1:
                return i
        return None

    a_inv = mod_inverse(a, 26)
    if a_inv is None:
        print("No modular inverse exists for key =", a)
        return

    ciphertext = text.upper()
    plaintext = ""
    for ch in ciphertext:
        if ch.isalpha():
            shift = ((ord(ch) - ord('A') - b) * a_inv) % 26
            plaintext += chr(shift + ord('A'))
        else:
            plaintext += ch
    print("Affine Ciphertext: " + text + "\nDecrypted Plaintext: " + plaintext)

exitkey=0
exit_key=0
while exitkey!=1:
    affineEncrypt()
    exitkey = int(input("Enter the exit key: "))
while exit_key!=1:
    affineDecrypt()
    exit_key = int(input("Enter the exit key: "))

'''
using the affine encrypt, we got the key as (5,6)
'''

'''
using the key obtained, we can use it in decrypt function to get back the original plaintext using the decrypt function
and using that we get the plain text was
"THEBESTOFAFIGHTISMAKINGUPAKTERWARDS"
or we say
The best of a fight is making up akterwards 
'''