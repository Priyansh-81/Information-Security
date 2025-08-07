'''
John is reading a mystery book involving cryptography. In one part of the book, the author
gives a ciphertext "CIW" and two paragraphs later the author tells the reader that this is a shift
cipher and the plaintext is "yes". In the next chapter, the hero found a tablet in a cave with
"XVIEWYWI" engraved on it. John immediately found the actual meaning of the ciphertext.
Identify the type of attack and plaintext
'''

'''
it is a shift cipher as it is mentioned.
CIW->YES

this appears to be ceaser cipher
'''
def CeaserEncrypt(text):
    key = int(input("Enter the key for additive cipher: "))
    plaintext = text.replace(" ", "").upper()
    ciphertext = ""
    for ch in plaintext:
        if ch.isalpha():
            shift = (ord(ch) - ord('A') + key) % 26
            ciphertext += chr(shift + ord('A'))
        else:
            ciphertext += ch
    print("Original plaintext: " + text + "\nAdditive Ciphertext: " + ciphertext)
    return ciphertext

def CeaserDecrypt(text):
    key = int(input("Enter the key for additive cipher: "))
    ciphertext = text.upper()
    plaintext = ""
    for ch in ciphertext:
        if ch.isalpha():
            shift = (ord(ch) - ord('A') - key) % 26
            plaintext += chr(shift + ord('A'))
        else:
            plaintext += ch
    print("Additive Ciphertext: " + text + "\nDecrypted Plaintext: " + plaintext)

plaintext = "YES"
exitkey=0
exit_key=0
while exitkey!=1:
    CeaserEncrypt(plaintext)
    exitkey = int(input("Enter the exit key: "))
while exit_key!=1:
    ceaser = "XVIEWYWI"
    CeaserDecrypt(ceaser)
    exit_key = int(input("Enter the exit key: "))


'''
it appears that the key is 4, and the plaintext so obtained will be TREASUSE

This is an example of known plaintext attack
'''