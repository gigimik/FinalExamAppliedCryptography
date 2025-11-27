from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib


BASE_DIR = Path(__file__).resolve().parent
ALICE_FILE = BASE_DIR / "alice_message.txt"
ENCRYPTED_FILE = BASE_DIR / "encrypted_file.bin"
ENCRYPTED_AES_KEY_FILE = BASE_DIR / "aes_key_encrypted.bin"
DECRYPTED_FILE = BASE_DIR / "decrypted_message.txt"
PUBLIC_KEY_FILE = BASE_DIR / "public.pem"
PRIVATE_KEY_FILE = BASE_DIR / "private.pem"


def generate_rsa_for_bob():
    if PRIVATE_KEY_FILE.exists() and PUBLIC_KEY_FILE.exists():
        print("[*] Bob RSA keys already exist.")
        return

    print("[*] Generating RSA keypair for Bob...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    print("[*] Saved Bob's keys: public.pem, private.pem")


def load_rsa_keys():
    with open(PRIVATE_KEY_FILE, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    with open(PUBLIC_KEY_FILE, "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return private_key, public_key


def compute_sha256(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha256(data).hexdigest()


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


def alice_encrypt(public_key):
    from os import urandom

    plaintext = ALICE_FILE.read_bytes()
    print(f"[*] Alice: read {len(plaintext)} bytes from alice_message.txt")

    original_hash = compute_sha256(ALICE_FILE)
    print(f"[*] Alice: original SHA-256 = {original_hash}")

    aes_key = urandom(32)
    iv = urandom(16)

    ciphertext = encrypt_aes_cbc(aes_key, iv, plaintext)

    with open(ENCRYPTED_FILE, "wb") as f:
        f.write(iv + ciphertext)
    print("[*] Alice: wrote encrypted_file.bin")

    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    with open(ENCRYPTED_AES_KEY_FILE, "wb") as f:
        f.write(encrypted_aes_key)
    print("[*] Alice: wrote aes_key_encrypted.bin")

    return original_hash


def bob_decrypt(private_key, original_hash: str):
    enc_key = ENCRYPTED_AES_KEY_FILE.read_bytes()
    aes_key = private_key.decrypt(
        enc_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    print("[*] Bob: decrypted AES key")

    data = ENCRYPTED_FILE.read_bytes()
    iv, ciphertext = data[:16], data[16:]
    plaintext = decrypt_aes_cbc(aes_key, iv, ciphertext)
    DECRYPTED_FILE.write_bytes(plaintext)
    print("[*] Bob: wrote decrypted_message.txt")

    decrypted_hash = compute_sha256(DECRYPTED_FILE)
    print(f"[*] Bob: decrypted SHA-256 = {decrypted_hash}")

    if decrypted_hash == original_hash:
        print("[+] Integrity check PASSED")
    else:
        print("[-] Integrity check FAILED")


def main():
    print("=== Task 2: Secure File Exchange Using RSA + AES ===")

    if not ALICE_FILE.exists():
        raise FileNotFoundError("alice_message.txt not found.")

    generate_rsa_for_bob()
    private_key, public_key = load_rsa_keys()

    print("\n--- Alice encrypts file ---")
    original_hash = alice_encrypt(public_key)

    print("\n--- Bob decrypts file ---")
    bob_decrypt(private_key, original_hash)

    print("\n[*] Task 2 finished. Check decrypted_message.txt.")


if __name__ == "__main__":
    main()
