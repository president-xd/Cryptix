# Cryptix Package Usage

## Overview

The Cryptix a powerful python library which provides decryption functions for various ciphers. Below are examples demonstrating how to use the decryption functions for different ciphers included in the package.

## Supported Ciphers

- Caesar Cipher
- Vigenère Cipher
- Affine Cipher
- Hill Cipher
- Beaufort Cipher
- Rail Fence Cipher
- Playfair Cipher
- Bacon Cipher
- Columnar Transposition Cipher
- One-Time Pad Cipher
- XOR Cipher
- Atbash Cipher
- ROT13 Cipher
- And many More Functionalities

## Sample Usage

### Caesar Cipher

```python
from cryptix import Cryptix

ciphertext = "Khoor Zruog"  # Encrypted with a shift of 3
shift = 3
plaintext = Cryptix.decrypt_caesar(ciphertext, shift)
print("Caesar Cipher Decryption:", plaintext)
```
### Hill Cipher
```python

from cryptix import Cryptix

ciphertext = "Xhpc yb fggw"  # Example encrypted text
key_matrix = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]
plaintext = Cryptix.decrypt_hill(ciphertext, key_matrix)
print("Hill Cipher Decryption:", plaintext)

```


