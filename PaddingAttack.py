import urllib.request
import urllib.parse
import urllib.error
import sys
import asyncio
from typing import Dict, List

TARGET = 'http://crypto-class.appspot.com/po?er='


class PaddingOracle(object):
    def query(self, q):
        target = TARGET + urllib.parse.quote(q)   # Create query URL
        print(target)
        req = urllib.request.Request(target)      # Send HTTP request

        try:
            f = urllib.request.urlopen(req)       # Wait for response
        except urllib.error.HTTPError as e:
            
            if e.code == 404:
                print("Good padding!")
                return True   # good padding
            return False      # bad padding

if __name__ == "__main__":
    po = PaddingOracle()
    #We have the following supposedly imtercepted ciphertext, we will try to decrypt it using the padding oracle attack
    cipher_text="f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4"
    #we convert the ciphertext to bytes and divide by blocks to make the manipulation needed for the attack
    cipher_bytes = bytes.fromhex(cipher_text)
    cipher_blocks=[bytearray(cipher_bytes[i:i+16]) for i in range(0, len(cipher_bytes), 16)]
    #We will also have a table to store the intermediate values of the attack
    intermediate_values = [[0]*16 for _ in range(len(cipher_blocks))]
    #Now, lets create the function that we will use to try to find the intermediate values
    def guess_byte(previous_block:bytearray,current_block:bytearray,byte_number:int,byte_guess:int)->int:
        """ 
        We create the new ciphertext with the byte guess and we query the oracle to see if the padding is correct
        """
        test_previous_block=bytearray(previous_block).copy()
        #we change the byte we want to guess to the byte guess
        test_previous_block[byte_number]=byte_guess
        test_block=[test_previous_block]+[current_block]
        new_ciphertext_hex="".join([c.hex() for c in test_block])
        print(new_ciphertext_hex)
        if po.query(new_ciphertext_hex) == True:
            return byte_guess
        #if the padding is correct, we return the byte guess, otherwise we return -1 to indicate that the guess was incorrect
        return -1
    for number_of_block in range(len(cipher_blocks)-1,0,-1):
        for byte_number in range(15,-1,-1):
            if byte_number<15:
                    previous_block=cipher_blocks[number_of_block-1].copy()
                    #we change the bytes that we have already found to the correct padding value
                    for j in range(byte_number+1,16):
                        previous_block[j]=intermediate_values[number_of_block][j] ^ (16-byte_number)
            else:
                    previous_block=cipher_blocks[number_of_block-1]
            #possibly_bytes= await asyncio.gather(*[guess_byte(previous_block,cipher_blocks[3],byte_number,i) for i in range 256])
            for i in range(256):
                #Avoid the case where we have a correct padding because of the original ciphertext, we know that the last byte of the original ciphertext is 0x04, so if we are trying to guess the last byte and we guess 0x04, we will have a correct padding, but it will not be because of our guess, but because of the original ciphertext, so we will skip that case
                if byte_number == 15 and i == cipher_blocks[number_of_block-1][15]:
                    continue
                correct_byte=guess_byte(previous_block,cipher_blocks[number_of_block],byte_number,i)
                #if we find a byte different from -1, this means that we have found a correct byte and therefore can calculate the intermidiate value
                if correct_byte!=-1:
                    print("Found correct byte: %d" % correct_byte)
                    intermediate_values[number_of_block][byte_number]=correct_byte ^ (16-byte_number)
                    break
    #When we have all the intermediate values, we can find the plaintext by xoring the intermediate values with the previous block
    plaintext_message=""
    for i in range(1,len(cipher_blocks)):
        plaintext_block=bytearray(16)
        for j in range(16):
            plaintext_block[j]=intermediate_values[i][j] ^ cipher_blocks[i-1][j]
        plaintext_message+=plaintext_block.decode('utf-8')
    print(plaintext_message)