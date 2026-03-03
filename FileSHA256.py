import os
import math
import hashlib
from unittest import result

#define the file path
#file_path = "src/6.2.birthday.mp4_download"
file_path= "src/6.1.intro.mp4_download"

with open(file_path, "rb") as f:
    file_bytes = f.read()
#now we define a function to calculate the hash of the function based on the sequential alghoritm described
def calculate_hash(data:bytes)->str:
    size=len(data)
    block_size=1024
    number_of_blocks=math.ceil(size/block_size)
    size_last_block=size%block_size
    #we define the start and the end for the first iteration and the previous hash

    end=size if size>0 else 0
    start=end-size_last_block if size_last_block!=0 else end-block_size
    previous_hash=''
    #we are going the final block result of the operation in a dictionary so any block and the previous hash can be looked up easily and a counter to know which key 
    #we are going to used in the cycle
    block_hashes={i:'' for i in range(number_of_blocks+1)}
    counter=number_of_blocks
    #Then we define the iteration starting from the last block
    for i in range(number_of_blocks):
        block=data[start:end]
        if previous_hash!='':
            block_hashes[counter]=block+previous_hash
        else:
            block_hashes[counter]=block
        #update the variables and calculate the hash of the block
        previous_hash=hashlib.sha256(block_hashes[counter]).digest()
        end=start
        start=start-block_size if start-block_size>=0 else 0
        counter-=1
    return previous_hash.hex(), block_hashes

if __name__=="__main__":
    result, block_hashes=calculate_hash(file_bytes)
    print(result)

