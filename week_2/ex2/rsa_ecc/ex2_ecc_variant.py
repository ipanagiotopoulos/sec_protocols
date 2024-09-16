import time
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

# Generate ECC key pair


def create_key_pair(name):
    private_key = ECC.generate(curve='P-256')  # P-256 is a popular ECC curve
    public_key = private_key.public_key()

    # Save keys to files
    with open(f"{name}_ECC_Private_Key.pem", 'wt') as priv_file:
        priv_file.write(private_key.export_key(format='PEM'))
    with open(f"{name}_ECC_Public_Key.pem", 'wt') as pub_file:
        pub_file.write(public_key.export_key(format='PEM'))

    print(f"ECC keys {name}_ECC_Private_Key.pem and {name}_ECC_Public_Key",
          ".pem have been generated.")

# ECC encryption (sign the message)


def encrypt(private_key_path, plaintext):
    with open(private_key_path, 'rt') as priv_file:
        private_key = ECC.import_key(priv_file.read())
    signer = DSS.new(private_key, 'fips-186-3')
    hash_obj = SHA256.new(plaintext.encode())
    signature = signer.sign(hash_obj)
    return signature

# ECC decryption (verify the signature)


def decrypt(public_key_path, signature, plaintext):
    with open(public_key_path, 'rt') as pub_file:
        public_key = ECC.import_key(pub_file.read())
    verifier = DSS.new(public_key, 'fips-186-3')
    hash_obj = SHA256.new(plaintext.encode())
    try:
        verifier.verify(hash_obj, signature)
        return "Message verified!"
    except ValueError:
        return "Message could not be verified!"

# Create a text file with a paragraph to sign


def create_file():
    paragraph = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
    with open("sample_text.txt", 'w') as file:
        file.write(paragraph)
    return paragraph

# Signing


def encryption(name):
    # ECC Key generation
    create_key_pair(name)

    # Generate the text file
    plain_text = create_file()

    # Signing
    start_time = time.time()
    signature = encrypt(f"{name}_ECC_Private_Key.pem", plain_text)
    signing_time = time.time() - start_time
    print(f"ECC signing lasted for: {signing_time:.6f} seconds")
    return signature, plain_text, signing_time

# Verifying


def decryption(name, signature, plain_text):
    start_time = time.time()
    result = decrypt(f"{name}_ECC_Public_Key.pem", signature, plain_text)
    verifying_time = time.time() - start_time
    print(f"ECC verification lasted for: {verifying_time:.6f} seconds")
    return result, verifying_time


def main():
    name = input("Enter a name for key generation (e.g., Alice): ")

    print("\n--- ECC Signing and Verifying ---")
    encrypted_text, plain_text, encryption_time = encryption(name)
    print(f"Signature is: {encrypted_text}")
    result, decryption_time = decryption(name, encrypted_text, plain_text)
    print(f"Result is: {result}")
    print("--      Times      --")
    print(f"ECC Signing time: {encryption_time:.6f} seconds")
    print(f"ECC Verification time: {decryption_time:.6f} seconds")


if __name__ == "__main__":
    main()
