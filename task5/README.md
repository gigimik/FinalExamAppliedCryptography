# Task 5 – Hashing & Integrity Check Utility

## Objective
This task demonstrates how cryptographic hashing is used to verify data integrity and detect unauthorized file modifications. The program calculates multiple cryptographic hashes for a file and verifies whether its contents have been altered.

The following hashing algorithms are used:
- MD5
- SHA-1
- SHA-256

---

## Files Included

hash_util.py        → Hashing and verification script  
original.txt        → Original file  
tampered.txt        → Modified file (simulates attack)  
hashes.json         → Stores original hash values  
README.md           → Documentation  

---

## How the Program Works

The script supports two execution modes:

### 1. Initialization Mode (Generate Hashes)
This mode computes hashes for the original file and stores them.

Command:
python hash_util.py init original.txt

Effect:
- Computes MD5, SHA-1, SHA-256
- Saves values in hashes.json

Example output:
[+] Hashes generated and saved to hashes.json

---

### 2. Verification Mode (Detect Tampering)
This mode recomputes hashes and compares them with saved values.

Command:
python hash_util.py check <filename>

Example:
python hash_util.py check original.txt

Output:
[+] INTEGRITY CHECK PASSED

Example (tampered file):
python hash_util.py check tampered.txt

Output:
[-] INTEGRITY CHECK FAILED — FILE WAS MODIFIED

---

## Example Result

The script correctly detects:
- An untouched file (PASS)
- A modified or empty file (FAIL)

This proves any change causes cryptographic fingerprints to change.

---

## Security Principles Demonstrated

### Data Integrity
Any file alteration results in new hash values.

### Tamper Detection
Mismatch = unauthorized modification detected.

### No Decryption
Hashes are one-way functions — original content cannot be recovered.

---

## Hash Algorithm Comparison

MD5      → Weak, collisions possible  
SHA-1    → Deprecated  
SHA-256  → Secure and recommended  

Only SHA-256 is considered safe for modern applications.

---

## Conclusion
This task successfully demonstrates integrity enforcement through hashing.  
It verifies that cryptographic hashes are reliable for detecting file manipulation across any system.

---

## Status
✅ Hash generation  
✅ Integrity verification  
✅ Tampering detection  
✅ Multi-hash validation  
✅ Task Complete  
