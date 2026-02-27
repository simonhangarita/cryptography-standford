from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

#The key and the final cypher text are given in hexadecimal format, we need to convert them to bytes before using them
CBC_KEY='140b41b22a29beb4061bda66b6747e14'
#CBC_final_cypher_text='5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253'
CBC_final_cypher_text='4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81'
def xor_bytes(a:bytes, b:bytes)->bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def encrypt_cbc(key:str, plaintext:str)->str:
    key_bytes=bytes.fromhex(key)
    iv=os.urandom(16)
    full_ciphertext=bytes.fromhex(plaintext)
    #AES in mode ECB allows us to encrypt individual blocks
    cipher=Cipher(algorithms.AES(key_bytes),modes.ECB())
    encryptor=cipher.encryptor()
    cipher_text=bytearray()
    previous_block=iv
    #lets do the loop of chaining the blocks
    for i in range(0, len(full_ciphertext), 16):
        #we need to take care of the padding, if the last block is less than 16 bytes, we need to pad it with PKCS7 padding
        if i+16>len(full_ciphertext):
            padder=padding.PKCS7(128).padder()
            padded_data=padder.update(full_ciphertext[i:].encode())+padder.finalize()
            plaintext_block=padded_data
        else:
            plaintext_block=full_ciphertext[i:i+16].encode()
        mixed_block=xor_bytes(plaintext_block, previous_block)
        cipher_block=encryptor.update(mixed_block)
        #the cipher block becomes the previous block for the next iteration
        cipher_text.extend(cipher_block)
        previous_block=cipher_block
    return (iv+bytes(cipher_text)).hex()
def decrypt_cbc(key:str, ciphertext:str)->str:
    key_bytes=bytes.fromhex(key)
    ciphertext_bytes=bytes.fromhex(ciphertext)
    iv=ciphertext_bytes[:16]
    ciphertext_blocks=ciphertext_bytes[16:]
    #We use AES in mode ECB to decrypt the blocks one by one
    cipher=Cipher(algorithms.AES(key_bytes),modes.ECB())
    decryptor=cipher.decryptor()
    plaintext=bytearray()
    previous_block=iv
    #lets do the loop to decrypt the blocks
    for i in range(0, len(ciphertext_blocks), 16):
        #Then again, we consider the padding, if the last block is less than 16 bytes, we need to consider it as well, but in this case we will handle the padding after decrypting all the blocks
        if i+16>len(ciphertext_blocks):
            padded_plaintext=decryptor.update(ciphertext_bytes[16:])+decryptor.finalize()
            unpadder=padding.PKCS7(128).unpadder()
            plaintext=unpadder.update(padded_plaintext)+unpadder.finalize()
            

        current_block=ciphertext_blocks[i:i+16]
        decrypted_block=decryptor.update(current_block)
        plain_block=xor_bytes(decrypted_block, previous_block)
        plaintext.extend(plain_block)
        previous_block=current_block
    return plaintext.decode()
print(decrypt_cbc(CBC_KEY,CBC_final_cypher_text))