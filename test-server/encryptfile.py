from curses import keyname
from hashlib import md5
from Crypto.Cipher import AES
from os import urandom
import subprocess
import os
import hashlib
from Crypto.Util.Padding import pad, unpad
def hashsha3(input):
    digest1 = hashlib.sha3_256()
    digest1.update(input)
    return digest1.digest()
def hashshake128(input):
    digest1 = hashlib.shake_128()
    digest1.update(input)
    return digest1.digest(16)
def encryptplaintext(plaintext,key):
    key=hashsha3(key)
    data_to_encrypt = plaintext 
    iv =hashshake128(key)
    data = data_to_encrypt
    cipher_encrypt = AES.new(key, AES.MODE_CFB, iv=iv)
    ciphered_bytes = cipher_encrypt.encrypt(pad(data,32))
    return ciphered_bytes
def decryptcipher(ciphertext,key):
    key=hashsha3(key)
    data_to_encrypt = ciphertext
    iv =hashshake128(key)
    ciphered_data = ciphertext
    cipher_decrypt = AES.new(key, AES.MODE_CFB, iv=iv)
    deciphered_bytes = unpad(cipher_decrypt.decrypt(ciphered_data),32)
    decrypted_data = deciphered_bytes
    return decrypted_data
def encrypt(in_file, out_file):
    bs = AES.block_size #16 bytes
    salt = urandom(bs) #return a string of random bytes
    cmd = "tpm2_unseal -c seal.ctx -p pcr:sha256:0,1,2,3"
    key = (subprocess.check_output(cmd, shell=True))
    key=hashsha3(key)
    iv =hashshake128(key)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    finished = False
    while not finished:
        chunk = in_file.read(1024 * bs) 
        if len(chunk) == 0 or len(chunk) % bs != 0:#final block/chunk is padded before encryption
            padding_length = (bs - len(chunk) % bs) or bs
            chunk += str.encode(padding_length * chr(padding_length))
            finished = True
        out_file.write(cipher.encrypt(chunk))

def decrypt(in_file, out_file):
    bs = AES.block_size
    #salt = in_file.read(bs)
    #key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cmd = "tpm2_unseal -c seal.ctx -p pcr:sha256:0,1,2,3"
    key = (subprocess.check_output(cmd, shell=True))
    key=hashsha3(key)
    iv =hashshake128(key)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    next_chunk = ''
    finished = False
    while not finished:
        chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
        if len(next_chunk) == 0:
            padding_length = chunk[-1]
            chunk = chunk[:-padding_length]
            finished = True 
        out_file.write(bytes(x for x in chunk)) 
#with open('key1.txt', 'rb') as in_file, open('key2.txt', 'wb') as out_file:
  # decrypt(in_file, out_file)