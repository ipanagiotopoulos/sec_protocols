import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

# Generate RSA key pair


def create_key_pair(name):
    private_key = RSA.generate(2048)  # 2048-bit RSA key
    public_key = private_key.publickey()

    # Save keys to files
    with open(f"{name}_Private_Key.pem", 'wb') as priv_file:
        priv_file.write(private_key.export_key())
    with open(f"{name}_Public_Key.pem", 'wb') as pub_file:
        pub_file.write(public_key.export_key())

    print(f"RSA keys {name}_Private_Key.pem and {name}_Public_Key.pem",
          "have been generated.")

# Encrypting messages while using an RSA public key


def encrypt(public_key_path, plain_text):
    with open(public_key_path, 'rb') as pub_file:
        public_key = RSA.import_key(pub_file.read())
    cipher_rsa = PKCS1_OAEP.new(public_key)
    cipher_text = cipher_rsa.encrypt(plain_text.encode())
    return cipher_text

# Decrypting messages while using an RSA private key


def decrypt(private_key_path, cipher_text):
    with open(private_key_path, 'rb') as priv_file:
        private_key = RSA.import_key(priv_file.read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher_rsa.decrypt(cipher_text)
    return decrypted_message.decode()

# Create a text file with a paragraph to encrypt


def create_file():
    paragraph = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum"
    with open("sample_text.txt", 'w') as file:
        file.write(paragraph)
    return paragraph


# Measure execution time for RSA


def encryption(name):
    # RSA Key generation
    create_key_pair(name)

    # Generate the text file
    plain_text = create_file()

    # Encryption
    start_time = time.time()
    cipher_text = encrypt(f"{name}_Public_Key.pem", plain_text)
    encryption_time = time.time() - start_time
    print(f"RSA Encryption took: {encryption_time:.6f} seconds")
    return cipher_text, encryption_time


def decryption(name, cipher_text):
    start_time = time.time()
    decrypted_text = decrypt(f"{name}_Private_Key.pem", cipher_text)
    decryption_time = time.time() - start_time
    print(f"RSA Decryption took: {decryption_time:.6f} seconds")
    return decrypted_text, decryption_time


def main():
    name = input("Enter a name for key generation (e.g., Alice): ")

    print("\n--- RSA Encryption and Decryption ---")
    encrypted_text, encryption_time = encryption(name)
    print(f"Cipher text  is: {binascii.hexlify(encrypted_text)}")
    decrypted_text, decryption_time = decryption(name, encrypted_text)
    print(f"Plain text is: {decrypted_text}")
    print("--      Times      --")
    print(f"RSA Encryption time: {encryption_time:.6f} seconds")
    print(f"RSA Decryption time: {decryption_time:.6f} seconds")


if __name__ == "__main__":
    main()
