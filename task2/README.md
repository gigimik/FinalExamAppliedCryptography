# Task 2 – Secure File Exchange Using RSA + AES (Hybrid Encryption)

## Objective
Demonstrate a secure hybrid encryption system using:
- RSA for key exchange
- AES-256 for file encryption
- SHA-256 for integrity verification

This task simulates a real-world scenario where Alice sends a file securely to Bob.

---

## Scenario Overview

Alice wants to send a secret file to Bob securely.  
To achieve this, a **hybrid encryption** approach is used:

- AES (symmetric encryption) is used to encrypt the file.
- RSA (asymmetric encryption) is used to encrypt the AES key.
- SHA-256 ensures file integrity.

---

## Files in This Task

| Filename | Description |
|----------|------------|
| `task2_secure_file_exchange.py` | Main Python script |
| `alice_message.txt` | Original plaintext file |
| `encrypted_file.bin` | AES-encrypted file (IV + ciphertext) |
| `aes_key_encrypted.bin` | AES key encrypted using Bob’s RSA public key |
| `decrypted_message.txt` | Final decrypted file |
| `public.pem` | Bob’s RSA public key |
| `private.pem` | Bob’s RSA private key |

---

## Encryption & Decryption Flow

### 1. RSA Key Generation (Bob)
Bob generates an RSA-2048 key pair:
- Private key → `private.pem`
- Public key → `public.pem`

The public key is shared with Alice.

---

### 2. File Encryption (Alice)

Alice performs the following steps:

1. Reads the file `alice_message.txt`
2. Computes SHA-256 hash of original file
3. Generates:
   - AES-256 key (32 bytes)
   - Random Initialization Vector (IV)
4. Encrypts file using:
```
AES-256-CBC + PKCS7 padding
```
5. Stores encrypted output as:
```
encrypted_file.bin (IV + ciphertext)
```
6. Encrypts AES key using Bob’s RSA public key:
```
RSA-OAEP with SHA-256
```
7. Saves encrypted AES key as:
```
aes_key_encrypted.bin
```

---

### 3. File Decryption (Bob)

Bob performs the following:

1. Decrypts AES key using `private.pem`
2. Extracts IV from `encrypted_file.bin`
3. Decrypts ciphertext using AES-256-CBC
4. Writes output to:
```
decrypted_message.txt
```

---

## Integrity Verification

Bob computes the SHA-256 hash of the decrypted file and compares it with Alice’s original hash.

If hashes match:
```
Integrity check PASSED
```

If hashes differ:
```
Integrity check FAILED
```

✅ In this run, integrity verification succeeded.

---

## AES vs RSA Comparison

| Feature | AES | RSA |
|--------|-----|-----|
| Type | Symmetric encryption | Asymmetric encryption |
| Speed | Very fast | Slow |
| Usage | Encrypts file | Encrypts AES key |
| Key size | 256 bits | 2048 bits |
| Security | Depends on secrecy of key | Depends on private key |

---

## Why Hybrid Encryption?

Encrypting full files with RSA is inefficient.  
Hybrid encryption provides:

- ✅ AES for performance
- ✅ RSA for secure key exchange

This architecture is used in TLS, PGP, VPNs, and secure messaging applications.

---

## Execution Instructions

Run from the `task2` folder:

```bash
python task2_secure_file_exchange.py
```

Expected output:

- RSA key generation (if missing)
- File encryption
- AES key RSA encryption
- File decryption
- Hash verification
- Integrity check PASSED

---

## Validation

Task is successful when:

- `decrypted_message.txt` == `alice_message.txt`
- SHA-256 hashes are identical
- Integrity check PASSED appears

---

## Conclusion

This task demonstrates:

- AES-256 file encryption
- RSA encrypted key exchange
- Hybrid cryptographic design
- SHA-256 integrity verification

It reflects real-world cryptographic systems in secure file transmission.
    