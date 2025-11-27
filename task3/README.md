# Task 3 – TLS Communication Inspection & Analysis

## Objective
This task analyzes how HTTPS communication is protected using TLS (Transport Layer Security).
The goal is to observe a real TLS handshake, extract cryptographic details, and explain how
confidentiality and integrity are achieved.

---

## Tools Used

OpenSSL  
Wireshark  
Web browser  
Kali Linux (Virtual Machine)

---

## Target Website

https://www.google.com

---

## OpenSSL Analysis

The following command was executed:

openssl s_client -connect www.google.com:443 -showcerts

### Observed TLS Parameters

TLS Version:
TLSv1.3

Cipher Suite:
TLS_AES_256_GCM_SHA384

Handshake Verification Result:
Verify return code: 0 (ok)

This confirms that the server certificate is trusted.

---

## Certificate Chain

Root Certificate Authority (CA):
CN=GlobalSign Root CA  
O=GlobalSign nv-sa  
C=BE  

Intermediate CA:
CN=GTS Root R4  
O=Google Trust Services LLC  
C=US  

Intermediate CA:
CN=WE2  
O=Google Trust Services  
C=US  

Leaf Certificate:
CN=www.google.com  

The server certificate is trusted through a complete chain leading
to a globally trusted root certificate.

---

## Wireshark TLS Handshake Analysis

A live packet capture was performed during an HTTPS connection using Wireshark.

### Handshake Messages Captured

Client Hello:
The client announces:
- Supported TLS versions
- Supported cipher suites
- Random values for session key generation
- Extensions like SNI (Server Name Indication)

Server Certificate:
The server sends:
- Its own certificate
- Intermediate certificates
- A chain to the trusted root CA

Key Exchange:
The key agreement uses:
TLS 1.3 Key Group: X25519MLKEM768

Ephemeral key exchange is used, providing Perfect Forward Secrecy.

---

## How TLS Provides Security

### Confidentiality
TLS encrypts data using symmetric encryption after the handshake.
In this session, AES-256-GCM is used to encrypt communication.

---

### Integrity
TLS protects data using authenticated encryption.
Any modification of encrypted traffic is detected.

---

### Authentication
Authentication is achieved using digital certificates.
The server proves identity using a trusted Certificate Authority chain.

---

## Special Notes

The HTTP 400 response was expected when using OpenSSL without sending
a valid HTTP request. TLS handshake succeeded and encryption was active.

---

## Conclusion

This analysis confirms that HTTPS communication:

- Uses strong encryption
- Verifies server authenticity
- Protects against eavesdropping
- Prevents tampering

TLS ensures confidentiality, integrity, and trust through 
public-key infrastructure and secure cryptographic protocols.

---

## Files in Task Folder

tls_summary.txt  
openssl_output.png  
wireshark_client_hello.png  
wireshark_server_certificate.png  
wireshark_key_exchange.png  
README.md
