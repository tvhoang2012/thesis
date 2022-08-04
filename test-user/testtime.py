import hashlib
import time
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
iv=os.urandom(16)
def encryptplaintext(plaintext,key):
    data_to_encrypt = plaintext 
    data = data_to_encrypt
    cipher_encrypt = AES.new(key, AES.MODE_CFB, iv=iv)
    ciphered_bytes = cipher_encrypt.encrypt(pad(data,32))
    return ciphered_bytes
def decryptcipher(ciphertext,key):
    data_to_encrypt = ciphertext
    ciphered_data = ciphertext
    cipher_decrypt = AES.new(key, AES.MODE_CFB, iv=iv)
    deciphered_bytes = unpad(cipher_decrypt.decrypt(ciphered_data),32)
    decrypted_data = deciphered_bytes
    return decrypted_data
t=0
in1=os.urandom(256)
key=os.urandom(32)
plaintext=os.urandom(128)
a=encryptplaintext(plaintext,key)
for i in range(10000):
    t0 = time.time()
    encryptplaintext(plaintext,key)
    t1 = time.time()
    t=t+(t1-t0)
print(t/10000 * 1000)