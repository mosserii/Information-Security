import string


class RepeatedKeyCipher:

    def __init__(self, key: bytes = bytes([0, 0, 0, 0, 0])):
        """Initializes the object with a list of integers between 0 and 255."""
        # WARNING: DON'T EDIT THIS FUNCTION!
        self.key = list(key)

    def encrypt(self, plaintext: str) -> bytes:
        """Encrypts a given plaintext string and returns the ciphertext."""
        text_bytes = plaintext.encode('latin-1')
        res = []
        for i in range(len(plaintext)):
            res.append(text_bytes[i] ^ int(self.key[i % len(self.key)]))  # todo check if we need res or not and if mod works well
        return bytes(res)

    def decrypt(self, ciphertext: bytes) -> str:
        """Decrypts a given ciphertext string and returns the plaintext."""
        return (RepeatedKeyCipher.encrypt(self, ciphertext.decode('latin-1'))).decode('latin-1')  # xor over xor gives plaintext



class BreakerAssistant:

    def plaintext_score(self, plaintext: str) -> float:
        """Scores a candidate plaintext string, higher means more likely."""
        # Please don't return complex numbers, that would be just annoying.
        score = 0
        english_letter_frequency = {'e': 12.0,
                           't': 9.10,
                           'a': 8.12,
                           'o': 7.68,
                           'i': 7.31,
                           'n': 6.95,
                           's': 6.28,
                           'r': 6.02,
                           'h': 5.92,
                           'd': 4.32,
                           'l': 3.98,
                           'u': 2.88,
                           'c': 2.71,
                           'm': 2.61,
                           'f': 2.30,
                           'y': 2.11,
                           'w': 2.09,
                           'g': 2.03,
                           'p': 1.82,
                           'b': 1.49,
                           'v': 1.11,
                           'k': 0.69,
                           'x': 0.17,
                           'q': 0.11,
                           'j': 0.10,
                           'z': 0.07}

        plaintext_letter_frequency = {}  # a dict contains the letter frequency in plaintext
        for letter in plaintext:
            if letter not in string.printable: # not an English letter
                return float('-inf')

            if letter.lower() in english_letter_frequency:
                if letter.lower() not in plaintext_letter_frequency:
                    plaintext_letter_frequency[letter.lower()] = 0  # first encounter with letter
                plaintext_letter_frequency[letter.lower()] += 1

        #here plaintext_letter_frequency data is ready
        for letter in plaintext:
            if letter.lower() in english_letter_frequency:
                score += english_letter_frequency[letter.lower()] * (plaintext_letter_frequency[letter.lower()])

        return score


    def brute_force(self, cipher_text: bytes, key_length: int) -> str:
        """Breaks a Repeated Key Cipher by brute-forcing all keys."""

        max_score = -1
        max_score_plaintext = ""
        for i in range(pow(2, 8 * key_length)):
            x = i
            key_array = []
            while x != 0:
                byte = x & 255 #extracting next byte
                key_array.append(byte)
                x //= 256 #jump to next byte (byte = 8 bits -> 2^8 = 256)
            while len(key_array) < key_length: #padding from left side if key_size is smaller than asked
                key_array.insert(0,0)

            key = RepeatedKeyCipher(bytes(key_array))
            plaintext = key.decrypt(cipher_text)
            current_score = self.plaintext_score(plaintext)

            if current_score >= max_score:
                max_score = current_score
                max_score_plaintext = plaintext

        return max_score_plaintext


    def smarter_break(self, cipher_text: bytes, key_length: int) -> str:
        """Breaks a Repeated Key Cipher any way you like."""
        n = len(cipher_text)
        pieces = [[] for i in range(key_length)]
        for i in range(n):
            # by definition of encryption in this assignment,
            # letter i and letter (i+key_length) in cipher were encrypted with the same byte of KEY
            pieces[i % key_length].append(cipher_text[i])


        key_array = []
        for piece in pieces:
            best_i = -1
            max_score_i = -1
            for i in range(256): #there are 256 options for the relevant **byte** of the key for each piece.
                current_key = RepeatedKeyCipher(bytes([i]))
                plaintext = current_key.decrypt(bytes(piece)) #all letters in this piece were encrypted with the same key : byte i
                current_score = self.plaintext_score(plaintext)

                if current_score >= max_score_i:
                    max_score_i = current_score
                    best_i = i
            key_array.append(best_i) #i is the byte of key that was probably used to encrypt the message

        res_key = RepeatedKeyCipher(bytes(key_array)) # we have the key as well :)
        return res_key.decrypt(cipher_text)

