# Task 1 – Encrypted Messaging App Prototype (RSA + AES)

## Goal

Implement a mini encrypted messaging system where:

- User A generates an RSA key pair and shares the public key.
- User B encrypts a secret message using AES-256 and encrypts the AES key with RSA.
- User A decrypts the AES key and then the message.

## Encryption Flow

1. **Key Generation (User A)**  
   - An RSA key pair (2048-bit) is generated.  
   - `rsa_public.pem` is shared with User B.  
   - `rsa_private.pem` is kept secret by User A.

2. **Message Encryption (User B)**  
   - Reads `message.txt` (plaintext).  
   - Generates a random 256-bit AES key and 128-bit IV.  
   - Encrypts the message using AES-256-CBC + PKCS7 padding.  
   - Stores `IV || ciphertext` in `encrypted_message.bin`.  
   - Encrypts the AES key with User A’s RSA public key (RSA-OAEP with SHA-256).  
   - Stores this in `aes_key_encrypted.bin`.

3. **Decryption (User A)**  
   - Uses `rsa_private.pem` to decrypt `aes_key_encrypted.bin` and recover the AES key.  
   - Splits `encrypted_message.bin` into IV and ciphertext.  
   - Decrypts the ciphertext with AES-256-CBC using the recovered key and IV.  
   - Saves the result as `decrypted_message.txt`.  

If everything works correctly, `decrypted_message.txt` is identical to `message.txt`.
