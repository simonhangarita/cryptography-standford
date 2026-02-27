from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

#The key and the final cypher text are given in hexadecimal format, we need to convert them to bytes before using them
CTR_KEY='36f18357be4dbd77f050515c73fcf9f2'
#CTR_final_cypher_text='69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329'
CTR_final_cypher_text='770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451'
def xor_bytes(a:bytes, b:bytes)->bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def encrypt_ctr(key:str, plaintext:str)->str:
    full_ciphertext=bytes.fromhex(plaintext)
    key_bytes=bytes.fromhex(key)
    iv=os.urandom(16)
    #AES in mode ECB allows us to encrypt individual blocks
    cipher=Cipher(algorithms.AES(key_bytes),modes.ECB())
    encryptor=cipher.encryptor()
    cipher_text=bytearray()
    counter=int.from_bytes(iv, byteorder="big")
    #lets do the loop of chaining the blocks
    for i in range(0, len(full_ciphertext), 16):
        
        plaintext_block=full_ciphertext[i:i+16]
        counter_bytes = counter.to_bytes(16, byteorder="big")
        new_key=encryptor.update(counter_bytes)
        mixed_block=xor_bytes(plaintext_block, new_key)
        #the cipher block becomes the previous block for the next iteration
        cipher_text.extend(mixed_block)
        counter+=1
    return (iv+bytes(cipher_text)).hex()
def decrypt_ctr(key:str, ciphertext:str)->str:
    key_bytes=bytes.fromhex(key)
    ciphertext_bytes=bytes.fromhex(ciphertext)
    iv=ciphertext_bytes[:16]
    ciphertext_blocks=ciphertext_bytes[16:]
    #We use AES in mode ECB to decrypt the blocks one by one
    cipher=Cipher(algorithms.AES(key_bytes),modes.ECB())
    encryptor = cipher.encryptor()
    plaintext=bytearray()
    counter=int.from_bytes(iv, byteorder="big")
    #lets do the loop to decrypt the blocks
    for i in range(0, len(ciphertext_blocks), 16):
        counter_bytes = counter.to_bytes(16, byteorder="big")
        current_block=ciphertext_blocks[i:i+16]
        decrypted_block=encryptor.update(counter_bytes)
        plain_block=xor_bytes(decrypted_block,current_block)
        plaintext.extend(plain_block)
        counter+=1
    return plaintext.decode()
print(decrypt_ctr(CTR_KEY,CTR_final_cypher_text))