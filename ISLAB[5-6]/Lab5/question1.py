def djb2_hash(s: str) -> int:
    # Initial hash value
    h = 5381

    for char in s:
        # Multiply by 33 and add ASCII value
        h = ((h << 5) + h) + ord(char)  # equivalent to h * 33 + ord(char)

        # Ensure thorough mixing (keep within 32-bit)
        h &= 0xFFFFFFFF

    return h

print(djb2_hash("hello")) 
print(djb2_hash("world"))