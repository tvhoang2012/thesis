from pickle import TRUE
import socket, ssl
import time
import hashlib
from Crypto.PublicKey import ECC
from Crypto.Util.number import inverse
from Crypto.Util.Padding import pad, unpad
import math
import encryptfile
import os
import connectdb
from _thread import *
#context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
#context.load_cert_chain(certfile="mycert.pem")
with open('key1.txt', 'rb') as in_file, open('key2.txt', 'wb') as out_file:
   encryptfile.decrypt(in_file, out_file)
f=open("key2.txt", "r")
line=f.readlines()
key=int(line[0])
key1=int(line[1])
f.close()
os.system('rm -f key2.txt')
delta_t=30
delta_tk=86400
n_p256=115792089210356248762697446949407573529996955224135760342422259061068512044369 
#key=74540744873497240236221846957338002700384447032604870008818918069549643237969
x=65324077562139981753027038154038858123792319981558830631401863943459538459694
y=112049366834566588725468740125562733337359436026148350017441910472447527649886
gy=36134250956749795798585127919587881956611106672985015071877198253568414405109
gx=48439561293906451759052585252797914202762949526041747995844080717082404635286
P=ECC.EccPoint(x,y,curve='P-256')
def hashsha3(input):
  digest1 = hashlib.sha3_256()
  digest1.update(input)
  return digest1.digest()
def register(input):
  input=input.split(",")
  id_u=input[1]
  exits=connectdb.checkuserexit(id_u,key1)
  if(len(exits)>0):
    return 0,0,0
  k_ui=id_u+str(key)
  k_ui=hashsha3(k_ui.encode())
  k_ui=int.from_bytes(k_ui, byteorder="big")
  d_i=input[1]+input[2]
  d_i=hashsha3(d_i.encode())
  c_i=hashsha3(d_i)
  c_i=int.from_bytes(c_i, byteorder="big")
  d_i=int.from_bytes(d_i, byteorder="big")
  a_i=k_ui^d_i
  return a_i,c_i,id_u
def registersever(recv):
  input=recv.split(",")
  id_s=input[1]
  connectdb.insertserver(id_s)
  k_s=id_s+str(key)
  k_sj=hashsha3(k_s.encode())
  k_sj=int.from_bytes(k_sj,byteorder="big")
  return k_sj
def update(recv):
  input=recv.split(",")
  DID=int(input[1])
  id_s=input[2]
  nx=int(input[3])
  ny=int(input[4])
  exits1=connectdb.checkserverexit(id_s)
  if(len(exits1)==0):
    return 0,0,0,0
  N=ECC.EccPoint(x=nx,y=ny,curve="p256")
  K=int(key)*N
  id_u=DID^int(K.x)
  len1=math.ceil(id_u.bit_length()/8)
  id_u=id_u.to_bytes(len1, byteorder="big")
  id_u=unpad(id_u,32)
  id_u=id_u.decode('UTF-8')
  exits=connectdb.checkuserexit(id_u,key1)
  if(len(exits)==0):
    return 0,0,0,0
  k_ui=id_u+str(key)
  k_ui=hashsha3(k_ui.encode())
  k_ui=int.from_bytes(k_ui, byteorder="big")
  k_sj=id_s+str(key)
  k_sj=hashsha3(k_sj.encode())
  k_sj=int.from_bytes(k_sj, byteorder="big")
  G=ECC.EccPoint(x=gx,y=gy,curve="p256")
  PK=k_sj*G
  k_ui1=inverse(k_ui,n_p256)
  t_r=int(time.time())
  #connectdb.updatetime(id_u,t_r)
  temp=str(k_sj)+id_u+str(t_r)
  temp=hashsha3(temp.encode())
  temp=int.from_bytes(temp, byteorder="big")
  c_ij=(k_ui1*temp)%(n_p256)
  C_ij=c_ij*G
  v=id_u+str(k_ui)+str(int(PK.x))+str(int(C_ij.x))+str(int(K.x))
  v=hashsha3(v.encode())
  v=int.from_bytes(v, byteorder="big")
  return PK,C_ij,v,t_r
def handle(conn):
  while True:
    #conn.write(b'GET / HTTP/1.1\n')
    data=conn.recv(1024)
    recv=data.decode('utf-8')
    if (recv.startswith("userregister")==True):
        a_i,c_i,id_u=register(recv)
        if(a_i==0):
          send="userexit"
          conn.sendall(send.encode("utf-8"))
        else:   
          send="OKDONE"+","+str(a_i)+","+str(c_i)+","+str(x)+","+str(y)+","+str(30)
          connectdb.insertuser(id_u,key1)
          conn.sendall(send.encode("utf-8"))        
    elif(recv.startswith("onlineupdate")==True):
        PK,C_ij,v,t_r=update(recv)
        if(t_r==0):
          send="userdontexit"
          conn.sendall(send.encode("utf-8"))
        else:
          send="OKUPDATEDONE"+","+str(int(PK.x))+","+str(int(PK.y))+","+str(int(C_ij.x))+","+str(int(C_ij.y))+","+str(v)+","+str(t_r)
          conn.sendall(send.encode("utf-8"))
        #print(f"Received: {data.decode('utf-8')}")
    elif(recv.startswith("serverregister")==True):
        k_sj=registersever(recv)
        send="serverregisterok,"+str(k_sj)+","+str(delta_t)+","+str(delta_tk)+","+str(x)+","+str(y)
        conn.sendall(send.encode("utf-8"))
    else:
        #a="Done"
        #conn.sendall(a.encode("utf-8"))
        #print(f"Received: {data.decode('utf-8')}")
        time.sleep(3)
        #break
sock = socket.socket()
sock.bind(('192.168.111.175', 4455))
sock.listen(5)
while True:
  conn, addr = sock.accept()
  """
  context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
  context.load_cert_chain(certfile="mycert.pem") 
  context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # optional
  context.set_ciphers('AES256+ECDH:AES256+EDH')
  """
  #conn = None
  #ssock, addr = sock.accept()
  try:
      #data = ssock.recv(1024)
      #print(data.decode('utf-8'))
      #print('Connected to: ' + addr[0] + ':' + str(addr[1]))
      start_new_thread(handle, (conn, ))
  except ssl.SSLError as e:
    print(e)
  finally:
      if conn:
        #sock.close()
        print("")
        #conn.close()
