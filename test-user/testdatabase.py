import mysql.connector
import qrcode
import os
import time
import cv2
from cryptography.hazmat.primitives.twofactor.totp import TOTP
from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.hazmat.primitives import hashes
import hashlib
import test
import base64
mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  password="Tvhoang2012@gmail",
  database="tmis"
)
mycursor = mydb.cursor()
def hashsha3(input):
  digest1 = hashlib.sha3_256()
  digest1.update(input)
  return digest1.digest()
"""
key=os.urandom(16)
key=test.encrypt(key)
totp = TOTP(key, 6, SHA512(), 30)
time_value = round(time.time(),3)
totp_value = totp.generate(time_value)
account_name='hoang'
issuer_name = 'Example Inc'
totp_uri = totp.get_provisioning_uri(account_name, issuer_name)
qr = qrcode.QRCode(version=1, box_size=10, border=5)
qr.add_data(totp_uri)
qr.make(fit=True)
img = qr.make_image(fill='black', back_color='white')
img.save("test.png")
image = cv2.imread('test.png')
cv2.imshow('image window', image)
cv2.waitKey(0)
cv2.destroyAllWindows()
sql = "INSERT INTO usertotp (name, keyotp) VALUES (%s, %s)"
val = (account_name,str(key.hex()))
mycursor.execute(sql, val)
mydb.commit()
print(mycursor.rowcount, "record inserted.")
"""
"""
mycursor.execute("SELECT keyotp FROM usertotp where name='hoang'")
myresult = mycursor.fetchall()
key= str(myresult)
key=key[3:len(key)-4]
key=bytes.fromhex(key)
totp = TOTP(key, 6, SHA512(), 30)
time_value = round(time.time(),3)
totp_value = totp.generate(time_value)
print(totp_value)
"""
#totp.verify(b'577972',time_value)
hash1=hashsha3(b"324325252345345")
hash2= base64.b64encode(hash1)
hash3=base64.b64decode(hash2)
time1=int(time.time())
"""
sql = "INSERT INTO user (hashname, time) VALUES (%s, %s)"
val = (hash2,time1)
mycursor.execute(sql, val)
mydb.commit()
print(mycursor.rowcount, "record inserted.")
"""

sql_select_query = """select time from user where hashname = %s""" 
mycursor.execute(sql_select_query, (hash2,))
myresult = mycursor.fetchall()
print(myresult)
a=str(myresult[0])
a=int(a[1:len(a)-2])
a=a+1
print(a)