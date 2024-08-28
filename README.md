# Cryptix Package Usage

## Overview

The Cryptix a powerful python library which provides decryption functions for various ciphers. Below are examples demonstrating how to use the decryption functions for different ciphers included in the package.

## Supported Ciphers

- **Vigenère Cipher**
- **Affine Cipher**
- **Hill Cipher**
- **Beaufort Cipher**
- **Rail Fence Cipher**
- **Playfair Cipher**
- **One-Time Pad Cipher**
- **XOR Cipher**
- **RSA Cipher**
- **Caeser Cipher**
- **Bacon Cipher**
- **AtBash Cipher**
- **RO13**
- **ROT5**
- **Columnar Transposition Cipher**

## Supported Encodings
- **Binary**
- **Hexadecimal**
- **Octal**
- **ASCII**
- **URL Encoding**
- **Unicode Point**
- **Base64**
- **Base32**
- **Base58**
- **Morse Code**

## Sample Usage

### Caesar Cipher

```python
from Cryptix import Cryptix

ciphertext = "Khoor Zruog"  # Encrypted with a shift of 3
shift = 3
plaintext = Cryptix.decrypt_caesar(ciphertext, shift)
print("Caesar Cipher Decryption:", plaintext)
```

## Conclusion
Simply there is the logic to decrypt all these algorthims, like if you want any cipher to decrypt, follow the trick below:
```python
from Cryptix import Cryptix
ciphertext = "Xhpc yb fggw"  # Example encrypted text
key_matrix = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]
plaintext = Cryptix.decrypt_hill(ciphertext, key_matrix)
print("Hill Cipher Decryption:", plaintext)

```
Just you want to type `decrypt_name`, like `decrypt_hill_cipher`, then either you want to print it or use a variable to store it and then print it.
The above example showed us that if you want to print it, first by saving its returing value to variable and then printing it.

### Other way to do
```python
from Cryptix import Cryptix
print(decrypt_caeser_cipher("HERE CIPHER TEXT COMES", "HERE COMES THE SWIFT FOR IT"))
```

Similary you can do it for decoding the mentioned encodings you have to use.
```python
encoded_text = "+++++++......++++++,-------"  # Example encoded text
plaintext = Cryptix.decode_morse_code(encoded_text)
print("Morse Code decoded text:", encoded_text)
```

### Other way to do it
```python
from Cryptix import Cryptix
print("Morse Code decoded text:", encoded_text)
```

