import pytest
from Cryptix.cryptix import Cryptix

class TestCryptix:

    def test_caesar_cipher(self):
        encrypted_text = "Khoor Zruog"
        key = 3
        expected_plaintext = "Hello World"
        decrypted_text = Cryptix.decrypt_caesar_cipher(encrypted_text, key)
        assert decrypted_text.lower() == expected_plaintext.lower()

    def test_vigenere_cipher(self):
        encrypted_text = "Lxfopvefrnhr"
        key = "LEMON"
        expected_plaintext = "attackatdawn"
        decrypted_text = Cryptix.decode_cipher(encrypted_text, key)
        assert decrypted_text.lower() == expected_plaintext.lower()

    def test_affine_cipher(self):
        encrypted_text = "Nyyn"
        a = 5
        b = 8
        expected_plaintext = "Test"
        decrypted_text = Cryptix.decrypt_affine_cipher(encrypted_text, a, b)
        assert decrypted_text == expected_plaintext

    def test_beaufort_cipher(self):
        encrypted_text = "YFXX"
        key = "KEY"
        expected_plaintext = "MZBN"
        decrypted_text = Cryptix.decrypt_beaufort_cipher(encrypted_text, key)
        assert decrypted_text == expected_plaintext

    def test_rail_fence_cipher(self):
        encrypted_text = "WECRLTEERDSOEE"
        key = 3
        expected_plaintext = "WLOTEEEECREDRS"
        decrypted_text = Cryptix.decrypt_rail_fence_cipher(encrypted_text, key)
        assert decrypted_text == expected_plaintext

    def test_playfair_cipher(self):
        key = "PLAYFAIR"
        matrix = Cryptix.matrix_generator(key)
        encrypted_text = "BMODZBXDNABEKUDM"
        expected_plaintext = "DHTRWDZCQPIHEFD"
        decrypted_text = Cryptix.decrypt_playfair_cipher(encrypted_text, matrix)
        assert decrypted_text == expected_plaintext

    def test_bacon_cipher(self):
        encrypted_text = "AABAAABAAA"
        expected_plaintext = "EI"
        decrypted_text = Cryptix.decrypt_bacon_cipher(encrypted_text)
        assert decrypted_text == expected_plaintext

    def test_columnar_transposition_cipher(self):
        encrypted_text = "hloolelwrd"
        key = "world"
        expected_plaintext = "rllohdewol"
        decrypted_text = Cryptix.decrypt_columnar_transposition_cipher(encrypted_text, key)
        assert decrypted_text == expected_plaintext

    def test_xor_cipher(self):
        encrypted_text = "10100110"
        key = 2
        expected_plaintext = "32322332"
        decrypted_text = Cryptix.decrypt_xor_cipher(encrypted_text, key)
        assert decrypted_text == expected_plaintext

    def test_atbash_cipher(self):
        encrypted_text = "ZGVHG"
        expected_plaintext = "ATEST"
        decrypted_text = Cryptix.decrypt_atbash_cipher(encrypted_text)
        assert decrypted_text == expected_plaintext

    def test_rot13_cipher(self):
        encrypted_text = "uryyb"
        expected_plaintext = "hello"
        decrypted_text = Cryptix.decrypt_rot13_cipher(encrypted_text)
        assert decrypted_text == expected_plaintext