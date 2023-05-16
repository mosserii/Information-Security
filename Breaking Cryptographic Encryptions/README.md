### **Breaking Cryptographic Encryptions**

In this exercise, we break Repeated key or RSA ciphers in many different ways.

Q1:
1. Encrypt a message into a repeated key cipher by XORing the message with the key (in bytes).
2. Decrypt a repeated key cipher into a message by XORing the cipher with the key (xoring twice gives back the message).
`Breaking a cipher without a key :`
3. A helper function (plaintext_score) : give a numeric score to a text such that a string containing a plausible text in English will recieve (with a higher probability) a higher score than a random string (see more in q1c.txt). 
4. A naive break of cipher : brute force all possible keys of a given length and return the most plausible text. Bad Complexity : O(2^(8*number_of_bytes))
5. A fast break of cipher (even of length > 10) : looking at the method of decrypting, one can notice that letter (i) and letter (i+key_length) in cipher were encrypted with the same byte of KEY, that gives us an advantage in finding the key (it is known in cryptography that one should not encrypt with the same key) - see more in q1e.txt!


Q2:
ATMs use RSA encryption in order to send details to a remote server for verification, therefore knowing the code of the ATM might help in finding vulnerabilities...
1. Breaking 4-digit credit card PIN code : given a RSA-encrypted PIN-code (RSA encrypted_PIN = PIN_Code^e (mod n)), we can break it if the programmer of the ATM forgot to limit tries, so we try all 10000 possibilities.
2. Breaking 8-9 digit credit card number : see in q2b.txt
3. Make the server always return True, while faking the signature of it as well - see more in q2c.txt.