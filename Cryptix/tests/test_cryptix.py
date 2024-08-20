import pytest
from Cryptix import Cryptix

class TestCryptix:
    def setup_class(self):
        self.Cryptix = Cryptix()

    # Sample encrypted text and expected plaintext for each cipher
    def test_caesar_cipher(self):
        encrypted_text = "Khoor Zruog"  # "Hello World" encrypted with Caesar Cipher with shift 3
        key = 3
        expected_plaintext = "Hello World"
        decrypted_text = self.Cryptix.decrypt_caesar_cipher(encrypted_text, key)
        assert decrypted_text == expected_plaintext

    def test_vigenere_cipher(self):
        encrypted_text = "LXFOPVEFRNHR"  # "ATTACKATDAWN" encrypted with key "LEMON"
        key = "LEMON"
        expected_plaintext = "ATTACKATDAWN"
        decrypted_text = self.Cryptix.decrypt_vigenere_cipher(encrypted_text, key)
        assert decrypted_text == expected_plaintext

    def test_affine_cipher(self):
        encrypted_text = "Jyyj"  # "Test" encrypted with a=5, b=8
        a = 5
        b = 8
        expected_plaintext = "Test"
        decrypted_text = self.Cryptix.decrypt_affine_cipher(encrypted_text, a, b)
        assert decrypted_text == expected_plaintext

    def test_beaufort_cipher(self):
        encrypted_text = "YFXX"  # "TEST" encrypted with key "KEY"
        key = "KEY"
        expected_plaintext = "TEST"
        decrypted_text = self.Cryptix.decrypt_beaufort_cipher(encrypted_text, key)
        assert decrypted_text == expected_plaintext

    def test_rail_fence_cipher(self):
        encrypted_text = "WECRLTEERDSOEE"  # "WEAREDISCOVERED" with 3 rails
        key = 3
        expected_plaintext = "WEAREDISCOVERED"
        decrypted_text = self.Cryptix.decrypt_rail_fence_cipher(encrypted_text, key)
        assert decrypted_text == expected_plaintext

    def test_playfair_cipher(self):
        encrypted_text = "BMODZBXDNABEKUDM"  # "HELLOMISTER" with key "PLAYFAIR"
        key = "PLAYFAIR"
        expected_plaintext = "HELLOMISTER"
        decrypted_text = self.Cryptix.decrypt_playfair_cipher(encrypted_text, key)
        assert decrypted_text == expected_plaintext

    def test_bacon_cipher(self):
        encrypted_text = "AAAAABABBA"  # "HELLO" with Bacon Cipher
        expected_plaintext = "HELLO"
        decrypted_text = self.Cryptix.decrypt_bacon_cipher(encrypted_text)
        assert decrypted_text == expected_plaintext

    def test_columnar_transposition_cipher(self):
        encrypted_text = "COEHLRTDLOE"  # "HELLO WORLD" with key "ZEBRAS"
        key = "ZEBRAS"
        expected_plaintext = "HELLO WORLD"
        decrypted_text = self.Cryptix.decrypt_columnar_transposition_cipher(encrypted_text, key)
        assert decrypted_text == expected_plaintext

    def test_xor_cipher(self):
        encrypted_text = "10100110"  # "HELLO" encrypted with key "KEY"
        key = "KEY"
        expected_plaintext = "HELLO"
        decrypted_text = self.Cryptix.decrypt_xor_cipher(encrypted_text, key)
        assert decrypted_text == expected_plaintext

    def test_atbash_cipher(self):
        encrypted_text = "ZGVHG"  # "HELLO" encrypted with Atbash Cipher
        expected_plaintext = "HELLO"
        decrypted_text = self.Cryptix.decrypt_atbash_cipher(encrypted_text)
        assert decrypted_text == expected_plaintext

    def test_rot13_cipher(self):
        encrypted_text = "URYYB"  # "HELLO" encrypted with ROT13
        expected_plaintext = "HELLO"
        decrypted_text = self.Cryptix.decrypt_rot13_cipher(encrypted_text)
        assert decrypted_text == expected_plaintext
