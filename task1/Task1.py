import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


BASE_DIR = Path(__file__).resolve().parent
MESSAGE_FILE = BASE_DIR / "message.txt"
RSA_PRIVATE_KEY_FILE = BASE_DIR / "rsa_private.pem"
RSA_PUBLIC_KEY_FILE = BASE_DIR / "rsa_public.pem"
ENCRYPTED_MESSAGE_FILE = BASE_DIR / "encrypted_message.bin"
ENCRYPTED_AES_KEY_FILE = BASE_DIR / "aes_key_encrypted.bin"
DECRYPTED_MESSAGE_FILE = BASE_DIR / "decrypted_message.txt"


def generate_rsa_keypair():
    """User A generates RSA key pair."""
    if RSA_PRIVATE_KEY_FILE.exists() and RSA_PUBLIC_KEY_FILE.exists():
        print("[*] RSA keys already exist.")
        return

    print("[*] Generating RSA key pair (User A)...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    public_key = private_key.public_key()

    # Save private key
    with open(RSA_PRIVATE_KEY_FILE, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Save public key
    with open(RSA_PUBLIC_KEY_FILE, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    print("[*] Saved rsa_private.pem and rsa_public.pem")


def load_rsa_keys():
    with open(RSA_PRIVATE_KEY_FILE, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    with open(RSA_PUBLIC_KEY_FILE, "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return private_key, public_key


def encrypt_aes_cbc(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


def decrypt_aes_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded_plaintext = dec.update(ciphertext) + dec.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded_plaintext) + unpadder.finalize()


def user_b_encrypt_message(public_key):
    """User B encrypts message with AES-256, then encrypts AES key with User A’s RSA public key."""
    from os import urandom

    plaintext = MESSAGE_FILE.read_bytes()
    print(f"[*] User B: read {len(plaintext)} bytes from message.txt")

    aes_key = urandom(32)  # 256-bit
    iv = urandom(16)       # 128-bit IV

    ciphertext = encrypt_aes_cbc(aes_key, iv, plaintext)

    # Store IV + ciphertext together
    with open(ENCRYPTED_MESSAGE_FILE, "wb") as f:
        f.write(iv + ciphertext)
    print(f"[*] User B: wrote encrypted_message.bin")

    # Encrypt AES key with RSA
    enc_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    with open(ENCRYPTED_AES_KEY_FILE, "wb") as f:
        f.write(enc_aes_key)
    print(f"[*] User B: wrote aes_key_encrypted.bin")


def user_a_decrypt_message(private_key):
    """User A decrypts AES key with RSA private key and then decrypts the message."""
    enc_key = ENCRYPTED_AES_KEY_FILE.read_bytes()
    aes_key = private_key.decrypt(
        enc_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    print("[*] User A: decrypted AES key")

    data = ENCRYPTED_MESSAGE_FILE.read_bytes()
    iv, ciphertext = data[:16], data[16:]
    plaintext = decrypt_aes_cbc(aes_key, iv, ciphertext)

    DECRYPTED_MESSAGE_FILE.write_text(plaintext.decode("utf-8"), encoding="utf-8")
    print("[*] User A: wrote decrypted_message.txt")


def main():
    print("=== Task 1: Encrypted Messaging App ===")

    if not MESSAGE_FILE.exists():
        MESSAGE_FILE.write_text("This is a secret message for Task 1.\n", encoding="utf-8")

    # User A: generate keys
    generate_rsa_keypair()
    private_key, public_key = load_rsa_keys()

    # User B: encrypt
    print("\n--- User B encrypts ---")
    user_b_encrypt_message(public_key)

    # User A: decrypt
    print("\n--- User A decrypts ---")
    user_a_decrypt_message(private_key)

    print("\n[*] Task 1 finished. Check decrypted_message.txt.")


if __name__ == "__main__":
    main()
