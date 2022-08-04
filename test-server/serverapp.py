from pickle import TRUE
import socket, ssl
import time
import hashlib
from Crypto.PublicKey import ECC
from Crypto.Util.number import inverse
import math
import encryptfile
import os
from Crypto.Util.Padding import pad, unpad
from _thread import *
#context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
#context.load_cert_chain(certfile="mycert.pem")
"""
with open('key1.txt', 'rb') as in_file, open('key2.txt', 'wb') as out_file:
   encryptfile.decrypt(in_file, out_file)
f=open("key2.txt", "r")
line=f.readlines()
key=int(line[0])
f.close()
os.system('rm -f key2.txt')
"""
n_p256=115792089210356248762697446949407573529996955224135760342422259061068512044369 
gy=36134250956749795798585127919587881956611106672985015071877198253568414405109
gx=48439561293906451759052585252797914202762949526041747995844080717082404635286
def hashsha3(input):
  digest1 = hashlib.sha3_256()
  digest1.update(input)
  return digest1.digest()
def registerserver(recv):
  input=recv.split(",")
  k_sj=input[1]
  delta_t=input[2]
  delta_tk=input[3]
  x=input[4]
  y=input[5]
  file = open("serverfile.txt", "w")
  content=delta_t+"\n"+delta_tk+"\n"+x+"\n"+y
  file.write(content)
  file.close()
  file= open("serverkey.txt","w")
  content=k_sj
  file.write(content)
  file.close()
def handlelogin(conn):
  while True:
    value1="23423545abc"
    value1="serverregister,"+value1
    conn.sendall(value1.encode("utf-8"))
    data=conn.recv(1024)
    recv=data.decode('utf-8')
    if (recv.startswith("serverregisterok")==True):
        registerserver(recv)
        conn.close()
        break
    else:
        #a="Done"
        #conn.sendall(a.encode("utf-8"))
        #print(f"Received: {data.decode('utf-8')}")
        time.sleep(3)
        conn.close()
        break 
def authentication(input):
    f=open("serverkey.txt", "r")
    line=f.readlines()
    key=int(line[0])
    f.close()
    f=open("serverfile.txt", "r")
    line=f.readlines()
    delta_t=int(line[0])
    delta_tk=int(line[1])
    f.close()
    input=input.split(",")
    t_s=int(time.time())
    t_u=int(input[6])
    t_r=int(input[7])
    if((t_s - t_u)>delta_t and (t_s - t_r)>delta_tk):
      return 0,0,0,0
    id_s=input[1]
    DID=int(input[2])
    w_x=int(input[3])
    w_y=int(input[4])
    W=ECC.EccPoint(x=w_x,y=w_y,curve="p256")
    q_u1=key*W
    id_u=DID^int(q_u1.x)
    len1=math.ceil(id_u.bit_length()/8)
    id_u=id_u.to_bytes(len1, byteorder="big")
    id_u=unpad(id_u,32)
    id_u=id_u.decode('UTF-8')
    temp=str(key)+id_u+str(t_r)
    temp=hashsha3(temp.encode())
    temp=int.from_bytes(temp, byteorder="big")
    q_u2=temp*W
    v=int(input[5])
    v1=id_u+str(int(q_u1.x))+str(int(q_u2.x))+str(t_u)
    v1=hashsha3(v1.encode())
    v1=int.from_bytes(v1, byteorder="big")
    if(v!=v1):
        return 0,0,0,0
    G=ECC.EccPoint(x=gx,y=gy,curve='p256')
    n_s=ECC.generate(curve='p256').d
    N_s=n_s*G
    sk_ij=str(int(q_u1.x))+str(int(q_u2.x))+str(int(N_s.x))
    sk_ij=hashsha3(sk_ij.encode())
    sk_ij1=int.from_bytes(sk_ij, byteorder="big")
    v_s=id_u+id_s+str(sk_ij1)+str(t_u)+str(t_s)
    v_s=hashsha3(v_s.encode())
    v_s=int.from_bytes(v_s, byteorder="big")
    return N_s,v_s,t_s,sk_ij
def handle(conn):
  sk_ij=0
  while True:
    if(sk_ij==0):
    #conn.write(b'GET / HTTP/1.1\n')
      data=conn.recv(1024)
      recv=data.decode('utf-8')
      if (recv.startswith("loginandaka")==True):
          N_s,v_s,t_s,sk_ij = authentication(recv)
          if(sk_ij==0):
            a="wrong-reject"
            conn.sendall(a.encode("utf-8"))
            break
          a="authenticationdone,"+str(int(N_s.x))+","+str(int(N_s.y))+","+str(int(t_s))+","+str(int(v_s))
          conn.sendall(a.encode("utf-8"))
      else:
        time.sleep(3)
    elif(sk_ij!=0):
        data=conn.recv(1024)
        try:
          data=encryptfile.decryptcipher(data,sk_ij)
          print(data.decode('utf-8'))
          send="hello"
          send=bytes(send, 'utf-8')
          send=encryptfile.encryptplaintext(send,sk_ij)
          conn.sendall(send)
        except:
           None
        #a="Done"
        #conn.sendall(a.encode("utf-8"))
        #print(f"Received: {data.decode('utf-8')}")
        #time.sleep(3)
        #break
    else:
        time.sleep(3)
      
#value=input()
value=input()
if(value.startswith("register")):
        PORT=4455
        HOST='192.168.111.175'
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect((HOST, PORT))
        #conn.send("Hello World!".encode("utf-8"))
                handlelogin(s)
            finally:
                s.close()
elif(value.startswith("start")):
  sock = socket.socket()
  sock.bind(('192.168.111.175', 4456))
  sock.listen(5)
  while True:
    conn, addr = sock.accept()
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
