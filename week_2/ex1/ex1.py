import time
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Generate AES-256 key


def create_key():
    return get_random_bytes(32)  # AES-256 cipher consists of 32 bytes


def encrypt(plaintext, shared_key):
    cipher = AES.new(shared_key, AES.MODE_EAX)
    nonce = cipher.nonce  # Nonce is required for EAX mode
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return nonce + ciphertext + tag  # Return nonce + ciphertext + tag for decryption

# Decrypt ciphertext using AES in EAX mode


def decrypt(ciphertext, shared_key):
    nonce = ciphertext[:16]  # Extract the nonce (first 16 bytes)
    tag = ciphertext[-16:]   # Extract the tag (last 16 bytes)
    # Extract the actual ciphertext in between
    actual_ciphertext = ciphertext[16:-16]
    cipher = AES.new(shared_key, AES.MODE_EAX, nonce=nonce)
    # Decrypt and verify
    return cipher.decrypt_and_verify(actual_ciphertext, tag)

# Base64 encode for safe transfer


def encode_base64(data):
    return base64.b64encode(data).decode()

# Base64 decode


def decode_base64(data):
    return base64.b64decode(data)

# Main function


def main():
    shared_key = create_key()
    print(f"Generated AES-256 Key (Base64): {encode_base64(shared_key)}")

    # Get plaintext input
    plaintext = input("Please enter the text that you want to encrypt: ")

    # Measure encryption time
    start_time = time.time()
    cipher_text = encrypt(plaintext, shared_key)
    encryption_time = time.time() - start_time

    print(f"Text after encryption (Base64): {encode_base64(cipher_text)}")
    print(f"Encryption lasted for {encryption_time:.6f} seconds")

    # Measure decryption time
    start_time = time.time()
    decrypted_text = decrypt(cipher_text, shared_key).decode()
    decryption_time = time.time() - start_time

    print(f"Text after decryption: {decrypted_text}")
    print(f"Decryption lasted for {decryption_time:.6f} seconds")

    # Compare times
    ratio = encryption_time / decryption_time
    if encryption_time > decryption_time:
        print(f"Encryption time was bigger that decryption by {ratio}times")
    else:

        print(f"Decryption took longer than encryption. {1/ratio} times")


if __name__ == "__main__":
    main()
