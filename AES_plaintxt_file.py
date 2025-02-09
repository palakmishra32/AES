from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

def generate_key():
    return get_random_bytes(16)  

def encrypt_text_file(file_path, key):
    
    with open(file_path, 'r') as file:
        text = file.read()    
    text_bytes = text.encode('utf-8')    
    iv = get_random_bytes(AES.block_size)
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
  
    padded_text = pad(text_bytes, AES.block_size)

    encrypted_text = cipher.encrypt(padded_text)
 
    encrypted_file_path = file_path + '.enc'
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(iv + encrypted_text)

    print(f"Text file encrypted and saved as {encrypted_file_path}")

def decrypt_text_file(encrypted_file_path, key):
   
    with open(encrypted_file_path, 'rb') as encrypted_file:
        iv_and_encrypted_text = encrypted_file.read()

    iv = iv_and_encrypted_text[:AES.block_size]
    encrypted_text = iv_and_encrypted_text[AES.block_size:]


    cipher = AES.new(key, AES.MODE_CBC, iv)

    decrypted_padded_text = cipher.decrypt(encrypted_text)

    decrypted_text_bytes = unpad(decrypted_padded_text, AES.block_size)

    decrypted_text = decrypted_text_bytes.decode('utf-8')

    decrypted_file_path = encrypted_file_path[:-4] + '_decrypted.txt'
    with open(decrypted_file_path, 'w') as decrypted_file:
        decrypted_file.write(decrypted_text)

    print(f"Text file decrypted and saved as {decrypted_file_path}")

if __name__ == "__main__":
    key = generate_key()
    print(f"Generated AES key: {base64.b64encode(key).decode()}")

    text_file_path = 'example.txt'  
    encrypt_text_file(text_file_path, key)

    encrypted_text_file_path = text_file_path + '.enc'
    decrypt_text_file(encrypted_text_file_path, key)