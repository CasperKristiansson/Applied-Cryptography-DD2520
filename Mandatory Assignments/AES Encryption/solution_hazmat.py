from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os


def aes_encrypt(key, block):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_block = encryptor.update(block) + encryptor.finalize()
    return encrypted_block


def main():
    file_path = os.path.join(os.path.dirname(__file__), "aes_sample.in")
    with open(file_path, "rb") as file:
        key = file.read(16)

        while True:
            block = file.read(16)
            if not block:
                break

            encrypted_block = aes_encrypt(key, block)
            print(encrypted_block.hex().upper())


if __name__ == "__main__":
    main()
