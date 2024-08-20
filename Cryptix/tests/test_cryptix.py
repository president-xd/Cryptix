import unittest
from Cryptix import Cryptix
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
class TestCryptix(unittest.TestCase):

    def test_decode_char(self):
        self.assertEqual(Cryptix.decode_char('C', 'A'), 'C')
        self.assertEqual(Cryptix.decode_char('E', 'B'), 'D')
        self.assertEqual(Cryptix.decode_char('D', 'C'), 'B')
    
    def test_decode_cipher(self):
        self.assertEqual(Cryptix.decode_cipher('CDE', 'ABC'), 'XYZ')
        self.assertEqual(Cryptix.decode_cipher('GIK', 'BDF'), 'HEL')
    
    def test_brute_force_decode(self):
        self.assertEqual(Cryptix.brute_force_decode('GIK', 'HEL'), 'BCD')

    def test_decrypt_hill_cipher(self):
        key_matrix = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]
        self.assertEqual(Cryptix.decrypt_hill_cipher('SENML', key_matrix), 'HELLO')

    def test_decrypt_beaufort_cipher(self):
        self.assertEqual(Cryptix.decrypt_beaufort_cipher('XUB', 'KEY'), 'HEL')

    def test_vigenere_bruteforce(self):
        # Testing a basic brute force on a short cipher
        result = Cryptix.vigenere_bruteforce('WPM', 'HEL', 'K')
        self.assertTrue(any(result.startswith('HEL') for result in result.values()))

    def test_decrypt_affine_cipher(self):
        self.assertEqual(Cryptix.decrypt_affine_cipher('LXFOPVEFRNHR', 5, 8), 'ATTACKATDAWN')

    def test_decrypt_rail_fence_cipher(self):
        self.assertEqual(Cryptix.decrypt_rail_fence_cipher('HWe olordll', 4), 'Hello World')

    def test_bruteforce_rail_fence_cipher(self):
        results = Cryptix.bruteforce('HWe olordll')
        self.assertIn(4, results)
        self.assertEqual(results[4], 'Hello World')

    def test_decrypt_playfair_cipher(self):
        matrix = Cryptix.matrix_generator('KEYWORD')
        self.assertEqual(Cryptix.decrypt_playfair_cipher('CIPH', matrix), 'TEST')

    def test_decrypt_one_time_pad_cipher(self):
        # This will need actual files to test properly; using mock data here
        # Assuming 'text.txt' contains "HELLO" and 'key.txt' contains "7,3,9,11,5"
        # self.assertEqual(Cryptix.decrypt_one_time_pad_cipher(), 'HELLO')

        # Mock test, replace with actual file reading
        text = 'HELLO'
        keys = [7, 3, 9, 11, 5]
        self.assertEqual(Cryptix.decrypt2_one_time_pad_cipher(text, keys), 'HELLO')

    def test_decrypt_xor_cipher(self):
        self.assertEqual(Cryptix.decrypt_xor_cipher('i`mmn!vdmu', 1), 'hello world')

    def test_decrypt_bacon_cipher(self):
        self.assertEqual(Cryptix.decrypt_bacon_cipher('AAAAA ABABA'), 'AB')

    def test_decrypt_columnar_transposition_cipher(self):
        self.assertEqual(Cryptix.decrypt_columnar_transposition_cipher('GDBD FECB', 'KEY'), 'HELLO WORLD')

    def test_decrypt_atbash_cipher(self):
        self.assertEqual(Cryptix.decrypt_atbash_cipher('GSV JFRXP YILDM'), 'THE QUEENS ARMY')

    def test_decrypt_caesar_cipher(self):
        self.assertEqual(Cryptix.decrypt_caesar_cipher('KHOOR', 3), 'HELLO')

    def test_decrypt_rot13_cipher(self):
        self.assertEqual(Cryptix.decrypt_rot13_cipher('Uryyb'), 'Hello')

if __name__ == '__main__':
    unittest.main()
