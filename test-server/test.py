import base64
import hashlib
from time import sleep
#import pyotp
import scipy.io as sio
import hashlib
import numpy as np
import FuzzyExtractor_1_parallel
import scipy.io as sio
import numpy as np
from Crypto.PublicKey import ECC
#import subprocess
#p = subprocess.Popen("glxinfo | grep OpenGL", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0]
#p=str(p)
#s = p.split("\\n")
#infogpu=s[1]
"""
str =base64.b32encode(b'taviethoang12345632432423432523543536546436')
totp = pyotp.TOTP(str,6,hashlib.sha512,None,10)
k=totp.now()
if totp.verify(k)==True:
    print("verify")
else:
    print("wrong")

#print(k)
sleep(10)
if totp.verify(k)==True:
    print("verify")
else:
    print("wrong")
#totp.now()
"""
def hashsha3(input):
  digest1 = hashlib.sha3_256()
  digest1.update(input)
  return digest1.digest()
def login(username, passw):
  data = sio.loadmat("tests/test_files/140_5.mat")
  b1 = data['a']
  b1=np.array(b1).flatten()
  b1=FuzzyExtractor_1_parallel.arraytosbin(b1)
  fe = FuzzyExtractor_1_parallel.FuzzyExtractor()
  p1=FuzzyExtractor_1_parallel.loadfile("file1.txt")
  r=fe.rep(b1, p1, num_processes=4)
  r=bytes(r)
  rpw=passw+str(r)
  rpw=hashsha3(rpw.encode())
  rpw=int.from_bytes(rpw, byteorder="big")
  d_i=username+str(rpw)
  d_i=hashsha3(d_i.encode())
  c_i=hashsha3(d_i)
  c_i=int.from_bytes(c_i, byteorder="big")
  return c_i
"""
f = open("filesave.txt", "r")
line=f.readlines()
print("username:")
#username=input()
username="hoang"
print("password:")
#passw=input()
passw="hoang123@G"
c_i=login(username,passw)
print(c_i)
print(line[1])
a=ECC.generate(curve='p256').d
print(a)
"""


