import string
import itertools
import urllib
import numpy as np
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import base64
from typing import List

EXCEPTION_MESSAGE = "Exception occurred: "

# Extended Morse code dictionary with some special characters
MORSE_CODE_DICT = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
    '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
    '8': '---..', '9': '----.', ' ': '/',
    '.': '.-.-.-', ',': '--..--', '?': '..--..', '\'': '.----.',
    '!': '-.-.--', '/': '-..-.', '(': '-.--.', ')': '-.--.-',
    '&': '.-...', ':': '---...', ';': '-.-.-.', '=': '-...-',
    '+': '.-.-.', '-': '-....-', '_': '..--.-', '"': '.-..-.',
    '@': '.--.-.',
    '{': '-.-..-', '}': '-.-.-.', '[': '-.--.', ']': '-.--.-',
    '<': '..-.-', '>': '---.-.'
}

class Cryptix:

    @staticmethod
    def decode_char(char, key_char):
        alpha_start = 65 if char.isupper() else 97
        decrypted_ord = (ord(char) - ord(key_char)) % 26 + alpha_start
        return chr(decrypted_ord)

    @staticmethod
    def decode_cipher(cipher, key):
        key_cycle = itertools.cycle(key)
        decrypted_text = ""

        for char in cipher:
            if char.isalpha():
                key_char = next(key_cycle).upper() if char.isupper() else next(key_cycle).lower()
                decrypted_text += Cryptix.decode_char(char, key_char)
            else:
                decrypted_text += char

        return decrypted_text

    @staticmethod
    def brute_force_decode(cipher, known_text):
        found_key = ""
        known_text2 = "".join(filter(str.isalpha, known_text))

        for index, digit in enumerate(known_text2):
            for potential_key in string.ascii_lowercase:
                test_key = found_key + potential_key
                decoded_text = Cryptix.decode_cipher("".join(filter(str.isalpha, cipher)), test_key)

                if decoded_text[: index + 1] == known_text2[: index + 1]:
                    found_key += potential_key
                    decodeee = Cryptix.decode_cipher(cipher, found_key)

                    if decodeee[: len(known_text)] == known_text:
                        return found_key

                    break
            else:
                print(f"No key found for digit: {digit}")
                break

        return found_key

    @staticmethod
    def mod_inverse(a, m):
        """Find the modular inverse of a under modulus m."""
        a = a % m
        for x in range(1, m):
            if (a * x) % m == 1:
                return x
        raise ValueError("No modular inverse exists")

    @staticmethod
    def decrypt_hill_cipher(ciphertext, key_matrix):
        """Decrypts the ciphertext using the Hill cipher with the provided key matrix."""
        try:
            key_matrix = np.array(key_matrix)
            determinant = int(np.round(np.linalg.det(key_matrix)))
            # Compute modular inverse of determinant
            determinant_inv = Cryptix.mod_inverse(determinant, 26)
            # Calculate the inverse matrix
            key_matrix_inv = determinant_inv * np.round(determinant * np.linalg.inv(key_matrix)).astype(int) % 26
            ciphertext_vectors = [ord(char.upper()) - ord('A') for char in ciphertext if char.isalpha()]
            plaintext_vectors = []

            for i in range(0, len(ciphertext_vectors), len(key_matrix)):
                vector = np.array(ciphertext_vectors[i:i+len(key_matrix)])
                decrypted_vector = np.dot(key_matrix_inv, vector) % 26
                plaintext_vectors.extend(decrypted_vector.astype(int))

            decrypted_text = ''.join(chr(int(v) + ord('A')) for v in plaintext_vectors)

            return decrypted_text
        except Exception as ex:
            print(EXCEPTION_MESSAGE, ex)

    @staticmethod
    def decrypt_beaufort_cipher(plaintext, key):
        """Decrypts plaintext using the Beaufort Cipher with the given key."""
        decrypted_text = ""
        for i in range(len(plaintext)):
            if plaintext[i].isalpha():
                # Convert the characters to uppercase and subtract 'A' to get a value between 0 and 25
                char_value = (ord(plaintext[i].upper()) - ord('A')) % 26
                key_value = (ord(key[i % len(key)].upper())-ord('A')) % 26
                # Apply the Beaufort Cipher algorithm to obtain the encrypted or decrypted character
                encrypted_char = chr(((key_value - char_value) % 26) + ord('A'))
                decrypted_text += encrypted_char
            else:
                # Keep the non-alphabetic character unchanged
                decrypted_text += plaintext[i]

        return decrypted_text

    @staticmethod
    def vigenere_bruteforce(cipher, known_text, key):
        brute_digit = 1
        while True:
            print("")
            for x in itertools.product(string.ascii_lowercase, repeat=brute_digit):
                new_key = key + "".join(x)
                new_text = Cryptix.decode_cipher(cipher, new_key)

                if new_text.startswith(known_text):
                    print(f"Key: {new_key} | Flag: {new_text}")
            try:
                try_again = input("Again Bruteforce? (y/n): ")
                if try_again.lower() == "n":
                    break

                additional_letters = input(f"Append letter to key {key}: ")
                key += additional_letters
            except KeyboardInterrupt:
                break

    @staticmethod
    def decrypt_affine_cipher(ciphertext, a, b):
        """Decrypts the ciphertext using the Affine cipher with keys a and b."""
        try:
            def mod_inverse(x, mod):
                for i in range(mod):
                    if (x * i) % mod == 1:
                        return i
                return None
            decrypted_text = []
            mod_inv_a = mod_inverse(a, 26)
            if mod_inv_a is None:
                raise ValueError("No modular inverse exists for the given 'a' value in the Affine Cipher.")

            for char in ciphertext:
                if char.isalpha():
                    base = ord('A') if char.isupper() else ord('a')
                    decrypted_char = chr((mod_inv_a * (ord(char) - base - b)) % 26 + base)
                    decrypted_text.append(decrypted_char)
                else:
                    decrypted_text.append(char)
            return ''.join(decrypted_text)
        except Exception as ex:
            print(EXCEPTION_MESSAGE, ex)

    @staticmethod
    def decrypt_rail_fence_cipher(input_string: str, key: int) -> str:
        """
        Generates a template based on the key and fills it in with
        the characters of the input string and then reading it in
        a zigzag formation.

        decrypt("HWe olordll", 4)
        'Hello World'

        """
        grid = []
        lowest = key - 1

        if key <= 0:
            raise ValueError("Height of grid can't be 0 or negative")
        if key == 1:
            return input_string

        temp_grid: list[list[str]] = [[] for _ in range(key)]  # generates template
        for position in range(len(input_string)):
            num = position % (lowest * 2)  # puts it in bounds
            num = min(num, lowest * 2 - num)  # creates zigzag pattern
            temp_grid[num].append("*")

        counter = 0
        for row in temp_grid:  # fills in the characters
            splice = input_string[counter : counter + len(row)]
            grid.append(list(splice))
            counter += len(row)

        output_string = ""  # reads as zigzag
        for position in range(len(input_string)):
            num = position % (lowest * 2)  # puts it in bounds
            num = min(num, lowest * 2 - num)  # creates zigzag pattern
            output_string += grid[num][0]
            grid[num].pop(0)
        return output_string


    @staticmethod
    def bruteforce(input_string: str) -> dict[int, str]:
        """Uses decrypt function by guessing every key

        >>> bruteforce("HWe olordll")[4]
        'Hello World'
        """
        results = {}
        for key_guess in range(1, len(input_string)):  # tries every key
            results[key_guess] = Cryptix.decrypt_rail_fence_cipher(input_string, key_guess)
        return results

    @staticmethod
    def matrix_generator(key):
        '''
        Generate a 5x5 matrix for the Playfair cipher
        Args: key (str) -- The key to generate the matrix
        Returns: 2D list -- A 5x5 matrix
        '''

        key = key.upper()
        unique = ""
        seen = set()
        for i in key:
            if i not in seen:
                if i == 'J': i = 'I'
                seen.add(i)
                unique += i

        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        for char in alphabet:
            if char not in seen:
                unique += char

        res = []
        for i in range(0, 25, 5):
            res.append(unique[i:i + 5])
        return res

    @staticmethod
    def decrypt_playfair_cipher(text, matrix):
        '''
        Decrypt a Playfair cipher
        Args: text (str) -- The encrypted text
            matrix (2D list) -- The matrix used to encrypt the text
        Returns: string -- The decrypted text
        '''

        position = {}
        for i in range(len(matrix)):
            for j in range(len(matrix[i])):
                ch = matrix[i][j]
                position[ch] = (i, j)

        two_char_diagram = []
        for i in range(0, len(text), 2):
            two_char_diagram.append(text[i:i + 2])

        res = []

        for a, b in two_char_diagram:
            row_a, col_a = position[a]
            row_b, col_b = position[b]

            if row_a == row_b:
                new_a = matrix[row_a][(col_a - 1) % 5]
                new_b = matrix[row_b][(col_b - 1) % 5]
            elif col_a == col_b:
                new_a = matrix[(row_a - 1) % 5][col_a]
                new_b = matrix[(row_b - 1) % 5][col_b]
            else:
                new_a = matrix[row_a][col_b]
                new_b = matrix[row_b][col_a]

            res.extend([new_a, new_b])

        decrypted_text = ""
        for char in res:
            if char != "X":
                decrypted_text += char

        return decrypted_text

    @staticmethod
    def decrypt_one_time_pad_cipher():
        """Decrypt using One-Time Pad cipher"""
        try:
            text_file_path = input("Enter the path to the text file: ")
            key_file_path = input("Enter the path to the key file: ")

            txt_file = open(text_file_path, "r", encoding='utf-8')
            text = list(txt_file.read())
            key_file = open(key_file_path, "r")
            keys = key_file.read().split(',')

            return "".join([chr(ord(text[i]) ^ int(keys[i])) for i in range(len(text))])
        except Exception as ex:
            print(EXCEPTION_MESSAGE, ex)
        finally:
            if 'txt_file' in locals() and txt_file is not None:
                txt_file.close()
            if 'key_file' in locals() and key_file is not None:
                key_file.close()

    @staticmethod
    def decrypt_xor_cipher_list(content: str, key: int) -> List[str]:
        """
        Decrypts 'content' using XOR cipher with a given 'key'.
        Returns the decrypted content as a list of chars.

        >>> decrypt_xor_cipher_list("", 5)
        []

        >>> decrypt_xor_cipher_list("i`mmn!vdmu", 1)
        ['h', 'a', 'l', 'l', 'o', ' ', 'w', 'e', 'l', 't']

        >>> decrypt_xor_cipher_list("hallo\\x00welt", 32)
        ['H', 'A', 'L', 'L', 'O', ' ', 'W', 'E', 'L', 'T']

        >>> decrypt_xor_cipher_list("hallo welt", 256)
        ['h', 'a', 'l', 'l', 'o', ' ', 'w', 'e', 'l', 't']
        """
        try:
            assert isinstance(key, int)
            assert isinstance(content, str)

            key %= 256

            return [chr(ord(ch) ^ key) for ch in content]
        except (ValueError, TypeError, Exception) as ex:
            print(f"{EXCEPTION_MESSAGE} {ex}")
            return []

    @staticmethod
    def decrypt_xor_cipher(content: str, key: int) -> str:
        """
        Decrypts 'content' using XOR cipher with a given 'key'.
        Returns the decrypted content as a string.

        >>> decrypt_xor_cipher_string("", 5)
        ''

        >>> decrypt_xor_cipher_string("i`mmn!vdmu", 1)
        'hallo welt'

        >>> decrypt_xor_cipher_string("hallo\\x00welt", 32)
        'HALLO WELT'
        >>> decrypt_xor_cipher_string("hallo welt", 256)
        'hallo welt'
        """
        try:
            assert isinstance(key, int)
            assert isinstance(content, str)

            key %= 256

            return ''.join(chr(ord(ch) ^ key) for ch in content)
        except (ValueError, TypeError, Exception) as ex:
            print(f"{EXCEPTION_MESSAGE} {ex}")
            return ""

    @staticmethod
    def decrypt_bacon_cipher(ciphertext):
        """
        Decrypts a string of Bacon's cipher text into plaintext.
        :param ciphertext: A string where each letter represents a part of Bacon's cipher.
        :return: The decrypted plaintext string.
        """
        bacon_dict = {
            'AAAAA': 'A', 'AAAAB': 'B', 'AAABA': 'C', 'AAABB': 'D',
            'AABAA': 'E', 'AABAB': 'F', 'AABBA': 'G', 'AABBB': 'H',
            'ABAAA': 'I', 'ABAAB': 'K', 'ABABA': 'L', 'ABABB': 'M',
            'ABBAA': 'N', 'ABBAB': 'O', 'ABBBA': 'P', 'ABBBB': 'Q',
            'BAAAA': 'R', 'BAAAB': 'S', 'BAABA': 'T', 'BAABB': 'U',
            'BABAA': 'W', 'BABAB': 'X', 'BABBA': 'Y', 'BABBB': 'Z'
        }

        plaintext = ""
        ciphertext = ciphertext.replace(' ', '').upper()  # Remove spaces and convert to uppercase
        for i in range(0, len(ciphertext), 5):
            cipher_group = ciphertext[i:i+5]
            plaintext += bacon_dict.get(cipher_group, '?')  # Use '?' for invalid groups
        return plaintext
    @staticmethod
    def decrypt_columnar_transposition_cipher(ciphertext, keyword):
        """Decrypts the ciphertext using the Columnar Transposition cipher with the provided keyword."""
        try:
            n_cols = len(keyword)
            n_rows = len(ciphertext) // n_cols
            sorted_keyword = sorted([(char, i) for i, char in enumerate(keyword)], key=lambda x: x[0])
            ordered_cols = [ciphertext[i*n_rows:(i+1)*n_rows] for i in range(n_cols)]
            matrix = [''] * n_cols
            for i, (_, original_pos) in enumerate(sorted_keyword):
                matrix[original_pos] = ordered_cols[i]
            decrypted_text = ''.join(''.join(row) for row in zip(*matrix))

            return decrypted_text
        except Exception as ex:
            print(EXCEPTION_MESSAGE, ex)

    @staticmethod
    def decrypt2_one_time_pad_cipher(text, keys):
        """Decrypt using One-Time Pad cipher (pre-loaded text and keys)"""
        try:
            return "".join([chr(ord(text[i]) ^ int(keys[i])) for i in range(len(text))])
        except Exception as ex:
            print(EXCEPTION_MESSAGE, ex)

    @staticmethod
    def decrypt_atbash_cipher(text):
        """Decrypt using Atbash cipher"""
        try:
            decrypted_text = ""
            for l in text:
                if string.ascii_lowercase.find(l, 0) != -1:
                    pos = string.ascii_lowercase.find(l, 0)
                    reverse = string.ascii_lowercase[::-1]
                    decrypted_text += reverse[pos]
                elif string.ascii_uppercase.find(l, 0) != -1:
                    pos = string.ascii_uppercase.find(l, 0)
                    reverse = string.ascii_uppercase[::-1]
                    decrypted_text += reverse[pos]
                else:
                    decrypted_text += l
            return decrypted_text
        except (ValueError, IndexError) as ex:
            print(EXCEPTION_MESSAGE, ex)

    @staticmethod
    def decrypt_caesar_cipher(text, key):
        """Decrypt using Caesar cipher"""
        try:
            decrypted_text = ""
            for l in text:
                if not(l >= 'A'and l <= 'Z' or l >= 'a'and l <= 'z'):
                    decrypted_text += l
                elif ord(l.upper()) - key < ord('A'):
                    decrypted_text += chr(ord('Z') - ord('A') + ord(l.upper()) + 1 - key)
                else:
                    decrypted_text += chr(ord(l.upper()) - key)
            return decrypted_text
        except (ValueError, IndexError, Exception) as ex:
            print(EXCEPTION_MESSAGE, ex)


    @staticmethod
    def decrypt_rot13_cipher(text):
        """Decrypt using ROT13 cipher"""
        try:
            decrypted_text = ""
            for l in text:
                if string.ascii_lowercase[:13].find(l, 0) != -1:
                    pos = string.ascii_lowercase[:13].find(l, 0)
                    opposite = string.ascii_lowercase[13:]
                    decrypted_text += opposite[pos]
                elif string.ascii_lowercase[13:].find(l, 0) != -1:
                    pos = string.ascii_lowercase[13:].find(l, 0)
                    opposite = string.ascii_lowercase[:13]
                    decrypted_text += opposite[pos]
                elif string.ascii_uppercase[:13].find(l, 0) != -1:
                    pos = string.ascii_uppercase[:13].find(l, 0)
                    opposite = string.ascii_uppercase[13:]
                    decrypted_text += opposite[pos]
                elif string.ascii_uppercase[13:].find(l, 0) != -1:
                    pos = string.ascii_uppercase[13:].find(l, 0)
                    opposite = string.ascii_uppercase[:13]
                    decrypted_text += opposite[pos]
                else:
                    decrypted_text += l
            return decrypted_text
        except (ValueError, IndexError) as ex:
            print(EXCEPTION_MESSAGE, ex)
    @staticmethod
    def decrypt_rsa_cipher(ciphertext: str, private_key_path: str):
        """Decrypts the ciphertext using the RSA cipher with the provided private key file path and prints results for different padding schemes."""
        try:
            # Decode the Base64-encoded ciphertext
            ciphertext_bytes = base64.b64decode(ciphertext)
            print("Decoded ciphertext bytes:", ciphertext_bytes)
            print()

            # Load the private key
            with open(private_key_path, 'rb') as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None
                )

            # Define padding schemes
            paddings = {
                "PKCS1v15": padding.PKCS1v15(),
                "OAEP (SHA256)": padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                ),
                "PKCS1v15 (legacy)": padding.PKCS1v15()  # Similar to PKCS1v15
            }

            # Try decrypting with different paddings and print results
            for pad_name, pad in paddings.items():
                try:
                    decrypted_bytes = private_key.decrypt(
                        ciphertext_bytes,
                        pad
                    )
                    decrypted_text = decrypted_bytes.decode('utf-8')
                    print(f"Decrypted with {pad_name}: {decrypted_text}")
                    print()
                except Exception as e:
                    print(f"Failed to decrypt with {pad_name}: {e}")
        except Exception as ex:
            print(EXCEPTION_MESSAGE, ex)
            return ""


    @staticmethod
    def decrypt_rot5_cipher(text):
        """Decrypt using ROT5 cipher"""
        decrypted_text = ""
        for l in text:
            if l.isdigit():
                index = int(l) - 5
                while index < 0:
                    index += 10
                decrypted_text += str(index % 10)
            else:
                decrypted_text += l
        return decrypted_text

    ## Below this are the functions for decoding the Encoded text

    @staticmethod
    def decode_binary_encoding(char: str) -> str:
        """Returns the decrypted text for Binary."""
        if " " not in char and len(char) > 8:
            raise ValueError("Input binary string seems to be missing spaces between bytes.")
        binary_translated = "".join(chr(int(i, 2)) for i in char.strip().split(" "))
        return binary_translated

    @staticmethod
    def decode_hexadecimal_encoding(char: str) -> str:
        """Returns the decrypted text for Hexadecimal."""
        if " " not in char and len(char) > 2:
            raise ValueError("Input hexadecimal string seems to be missing spaces between bytes.")
        hexadecimal_translated = "".join(chr(int(i, 16)) for i in char.strip().split(" "))
        return hexadecimal_translated

    @staticmethod
    def decode_octal_encoding(char: str) -> str:
        """Returns the decrypted text for Octal."""
        if " " not in char and len(char) > 3:
            raise ValueError("Input octal string seems to be missing spaces between bytes.")
        octal_translated = "".join(chr(int(i, 8)) for i in char.strip().split(" "))
        return octal_translated

    @staticmethod
    def decode_ascii_encoding(char: str) -> str:
        """Returns the decrypted text for ASCII."""
        if " " not in char:
            raise ValueError("Input ASCII string seems to be missing spaces between numbers.")
        ascii_translated = "".join(chr(int(i)) for i in str(char).split(" "))
        return ascii_translated

    @staticmethod
    def decode_url_encoding(char: str) -> str:
        """Returns the decrypted text for URL Encoding."""
        return urllib.parse.unquote(char)

    @staticmethod
    def decode_unicode_point_encoding(char: str) -> str:
        """Returns the decrypted text for Unicode."""
        return "".join(chr(int(uni, 16)) for uni in str(char).split(" "))

    @staticmethod
    def decode_base32_encoding(char: str) -> str:
        """Returns the decrypted text for Base32."""
        base32_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567="

        # Remove padding characters
        char = char.rstrip("=")

        # Map Base32 characters to their binary equivalents
        base32_to_bin = {c: format(base32_alphabet.index(c), '05b') if c in base32_alphabet else None for c in char}

        # Filter out None values and convert to binary string
        binary_string = ''.join(b for b in map(base32_to_bin.get, char) if b is not None)

        # Split binary string into 8-bit chunks and convert to ASCII
        decoded_text = ''.join(chr(int(binary_string[i:i+8], 2)) for i in range(0, len(binary_string), 8))

        return decoded_text

    @staticmethod
    def decode_base64_encoding(encoded_str: str) -> str:
        """Returns the decoded text for Base64."""
        base64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        padding = '='

        # Create a dictionary for Base64 to binary conversion
        base64_to_bin = {c: format(i, '06b') for i, c in enumerate(base64_alphabet)}

        # Remove padding characters
        encoded_str = encoded_str.rstrip(padding)

        # Convert Base64 string to binary string
        try:
            binary_string = ''.join(base64_to_bin[c] for c in encoded_str)
        except KeyError:
            raise ValueError("Error decoding Base64 string: contains invalid characters")

        # Handle padding to complete the binary string to byte-aligned length
        if len(binary_string) % 8 != 0:
            binary_string = binary_string + '0' * (8 - len(binary_string) % 8)

        # Convert binary string to bytes
        decoded_bytes = bytearray()
        for i in range(0, len(binary_string), 8):
            byte = binary_string[i:i+8]
            decoded_bytes.append(int(byte, 2))

        # Convert bytes to string
        try:
            decoded_text = decoded_bytes.decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError("Error decoding Base64 string: contains invalid UTF-8 characters")

        return decoded_text

    @staticmethod
    def decode_base58_encoding(char: str) -> str:
        """Returns the decrypted text for Base58."""
        base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz!#$%&'()*+,-./:;<=>?@[\]^_`{|}~"

        # Create a dictionary for Base58 to integer conversion
        base58_to_int = {c: i for i, c in enumerate(base58_alphabet)}

        # Convert Base58 string to integer
        num = 0
        for c in char:
            num = num * 58 + base58_to_int[c]

        # Convert integer to bytes
        decoded_bytes = bytearray()
        while num > 0:
            num, rem = divmod(num, 256)
            decoded_bytes.insert(0, rem)
        # Convert bytes to string
        try:
            decoded_text = bytes(decoded_bytes).decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError("Error decoding Base58 string: contains invalid UTF-8 characters")

        return decoded_text

    @staticmethod
    def decode_morse_code_encoding(morse_code):
        """Convert Morse code to text."""
        reverse_dict = {value: key for key, value in MORSE_CODE_DICT.items()}
        morse_code = morse_code.strip().split(' ')
        decoded_text = ''.join(reverse_dict.get(code, '') for code in morse_code)
        return decoded_text


############################################################################################################################################
                                            Encryption Functions begin here
############################################################################################################################################

    @staticmethod
    def encrypt_caeser_cipher(plaintext, shift):
        """
        Encrypts the input string using the Caesar cipher with the specified shift.

        Parameters:
        - plaintext (str): The string to be encrypted.
        - shift (int): The number of positions to shift each letter.

        Returns:
        - str: The encrypted string.
        """
        encrypted_text = []
    
        for char in plaintext:
            if char.isalpha():  # Check if the character is a letter
                # Determine if it's uppercase or lowercase
                start = ord('A') if char.isupper() else ord('a')
                # Encrypt the character and handle wrap-around using modulo operation
                encrypted_char = chr(start + (ord(char) - start + shift) % 26)
                encrypted_text.append(encrypted_char)
            else:
                # Non-alphabetic characters are added unchanged
                encrypted_text.append(char)
    
        return ''.join(encrypted_text)



