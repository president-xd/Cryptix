# tests/test_cryptix.py

import pytest
from Cryptix.cryptix import CaesarCipher, VigenereCipher  # Import the necessary classes or functions

def test_caesar_cipher():
    cipher = CaesarCipher()
    plaintext = "HELLO"
    key = 3
    encrypted = cipher.encrypt(plaintext, key)
    decrypted = cipher.decrypt(encrypted, key)
    assert decrypted == plaintext, "Caesar Cipher decryption failed"

def test_vigenere_cipher():
    
    decrypted = cipher.decrypt("", key)
    assert decrypted == plaintext, "Vigenere Cipher decryption failed"

# Add more tests for other ciphers and functionalities
