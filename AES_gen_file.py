from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os

def generate_key():
    return get_random_bytes(16)  


def encrypt_file(file_path, key, output_file):
    
    with open(file_path, 'rb') as file:
        file_data = file.read()

    
    iv = get_random_bytes(AES.block_size)    
    cipher = AES.new(key, AES.MODE_CBC, iv)    
    padded_data = pad(file_data, AES.block_size)    
    encrypted_data = cipher.encrypt(padded_data)
    
    with open(output_file, 'wb') as encrypted_file:
        encrypted_file.write(iv + encrypted_data)

    print(f"File encrypted and saved as {output_file}")


def decrypt_file(encrypted_file_path, key, output_file):
    
    with open(encrypted_file_path, 'rb') as encrypted_file:
        iv_and_encrypted_data = encrypted_file.read()

    
    iv = iv_and_encrypted_data[:AES.block_size]
    encrypted_data = iv_and_encrypted_data[AES.block_size:]    
    cipher = AES.new(key, AES.MODE_CBC, iv)    
    decrypted_padded_data = cipher.decrypt(encrypted_data)    
    decrypted_data = unpad(decrypted_padded_data, AES.block_size)

    
    with open(output_file, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)

    print(f"File decrypted and saved as {output_file}")


if __name__ == "__main__":
    
    key = generate_key()
    print(f"Generated AES key: {key.hex()}")

    
    input_file = "example.jpeg"       
    encrypted_file = "encrypted.bin"    
    decrypted_file = "decrypted.jpeg"    

    
    encrypt_file(input_file, key, encrypted_file)
    decrypt_file(encrypted_file, key, decrypted_file)

    print("Encryption and decryption completed successfully!")