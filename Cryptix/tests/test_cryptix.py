import pytest
from Cryptix import Cryptix

class TestCryptix:
    def setup_class(self):
        self.cryptix = Cryptix()

    # Sample encrypted text and expected plaintext for each cipher
    def test_caesar_cipher(self):
        encrypted_text = "Khoor Zruog"  # "Hello World" encrypted with Caesar Cipher with shift 3
        key = 3
        expected_plaintext = "Hello World"
        decrypted_text = self.cryptix.caesar_cipher_decrypt(encrypted_text, key)
        assert decrypted_text == expected_plaintext

    def test_vigenere_cipher(self):
        encrypted_text = "LXFOPVEFRNHR"  # "ATTACKATDAWN" encrypted with key "LEMON"
        key = "LEMON"
        expected_plaintext = "ATTACKATDAWN"
        decrypted_text = self.cryptix.vigenere_cipher_decrypt(encrypted_text, key)
        assert decrypted_text == expected_plaintext

    def test_affine_cipher(self):
        encrypted_text = "Jyyj"  # "Test" encrypted with a=5, b=8
        a = 5
        b = 8
        expected_plaintext = "Test"
        decrypted_text = self.cryptix.affine_cipher_decrypt(encrypted_text, a, b)
        assert decrypted_text == expected_plaintext

    def test_beaufort_cipher(self):
        encrypted_text = "YFXX"  # "TEST" encrypted with key "KEY"
        key = "KEY"
        expected_plaintext = "TEST"
        decrypted_text = self.cryptix.beaufort_cipher_decrypt(encrypted_text, key)
        assert decrypted_text == expected_plaintext

    def test_rail_fence_cipher(self):
        encrypted_text = "WECRLTEERDSOEE"  # "WEAREDISCOVERED" with 3 rails
        key = 3
        expected_plaintext = "WEAREDISCOVERED"
        decrypted_text = self.cryptix.rail_fence_cipher_decrypt(encrypted_text, key)
        assert decrypted_text == expected_plaintext

    def test_playfair_cipher(self):
        encrypted_text = "BMODZBXDNABEKUDM"  # "HELLOMISTER" with key "PLAYFAIR"
        key = "PLAYFAIR"
        expected_plaintext = "HELLOMISTER"
        decrypted_text = self.cryptix.playfair_cipher_decrypt(encrypted_text, key)
        assert decrypted_text == expected_plaintext

    def test_bacon_cipher(self):
        encrypted_text = "AAAAABABBA"  # "HELLO" with Bacon Cipher
        expected_plaintext = "HELLO"
        decrypted_text = self.cryptix.bacon_cipher_decrypt(encrypted_text)
        assert decrypted_text == expected_plaintext

    def test_columnar_transposition_cipher(self):
        encrypted_text = "COEHLRTDLOE"  # "HELLO WORLD" with key "ZEBRAS"
        key = "ZEBRAS"
        expected_plaintext = "HELLO WORLD"
        decrypted_text = self.cryptix.columnar_transposition_cipher_decrypt(encrypted_text, key)
        assert decrypted_text == expected_plaintext

    def test_one_time_pad_cipher(self):
        encrypted_text = "XLPHP"  # "HELLO" with key "XMCKL"
        key = "XMCKL"
        expected_plaintext = "HELLO"
        decrypted_text = self.cryptix.one_time_pad_cipher_decrypt(encrypted_text, key)
        assert decrypted_text == expected_plaintext

    def test_xor_cipher(self):
        encrypted_text = "10100110"  # "HELLO" encrypted with key "KEY"
        key = "KEY"
        expected_plaintext = "HELLO"
        decrypted_text = self.cryptix.xor_cipher_decrypt(encrypted_text, key)
        assert decrypted_text == expected_plaintext

    def test_atbash_cipher(self):
        encrypted_text = "ZGVHG"  # "HELLO" encrypted with Atbash Cipher
        expected_plaintext = "HELLO"
        decrypted_text = self.cryptix.atbash_cipher_decrypt(encrypted_text)
        assert decrypted_text == expected_plaintext

    def test_rot13_cipher(self):
        encrypted_text = "URYYB"  # "HELLO" encrypted with ROT13
        expected_plaintext = "HELLO"
        decrypted_text = self.cryptix.rot13_cipher_decrypt(encrypted_text)
        assert decrypted_text == expected_plaintext
