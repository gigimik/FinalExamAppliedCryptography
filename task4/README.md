# Task 4 – Email Encryption and Digital Signature (PGP)

## Objective
This task demonstrates how email messages can be secured using Public Key Cryptography (PGP), digital signatures, and encryption. The objective is to simulate secure internal company email communication with full confidentiality, integrity, and authentication.

---

## Scenario

Alice wants to send a confidential email to Bob securely. The message must be protected so that:

- No unauthorized person can read the message (Confidentiality)
- The message cannot be altered without detection (Integrity)
- The identity of the sender can be confirmed (Authentication)

---

## Files in this Task

original_message.txt — Original plaintext email  
signed_message.asc — Encrypted and digitally signed email  
decrypted_message.txt — Successfully decrypted message  
public.asc — Exported public key  
private.key — Exported private key  
signature_verification.txt — Explanation of sender verification  
README.md — Task documentation  

---

## Execution Environment

The task was performed in Kali Linux using GNU Privacy Guard (GPG).

---

## Process Overview

### Step 1 – Key Pair Generation

Alice generated a PGP key pair consisting of:

- A public key, which can be shared safely
- A private key, which must remain secret

This key pair is used for both encryption and signing.

---

### Step 2 – Message Creation

Alice wrote the message inside:

original_message.txt

This represents an internal company email.

---

### Step 3 – Signing and Encryption

Alice encrypted and digitally signed the message.

Encryption ensures that only the intended recipient can read the message.
The digital signature proves who sent the message.

The result is:

signed_message.asc

This file is both encrypted and signed.

---

### Step 4 – Decryption and Verification

Bob decrypted the message using the private key.

During decryption, GPG verified the signature automatically and displayed:

Good signature from "Alice"

If the content had been altered, verification would fail.

---

## What the Signature Proves

The digital signature guarantees:

Authentication — Confirms Alice is the sender  
Integrity — Ensures the message was not modified  
Non-repudiation — Alice cannot deny sending the message  

---

## Why PGP Is Secure

PGP combines:

- RSA for public-key encryption
- AES for fast symmetric encryption
- Hashing algorithms for integrity

This makes communication:

Secure  
Authentic  
Tamper-proof  

---

## Results Summary

The task successfully demonstrates:

Confidentiality  
Integrity  
Authentication  
Encryption  
Signature verification  

---

## Conclusion

This task simulates real-world secure email communication using PGP technology.

It demonstrates how encryption and digital signatures are used in corporate and
personal communication systems to prevent data leaks, impersonation, and tampering.

---

## Security Note

The private key is included in this repository only for educational purposes.

In real-world systems, private keys must NEVER be publicly shared.
