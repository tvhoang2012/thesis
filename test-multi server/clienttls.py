from pickle import TRUE
import socket, ssl
import time
import datetime
from matplotlib.pyplot import connect
import platform
import subprocess
from getmac import get_mac_address
HOST, PORT = '192.168.111.129', 443
def getgpu():
    p = subprocess.Popen("glxinfo | grep OpenGL", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0]
    p=str(p)
    s = p.split("\\n")
    infogpu=s[1]
    return infogpu
def getUTC():
  if(time.timezone<0):
    a="UTC-"+str(datetime.timedelta(seconds=-time.timezone))
  elif(time.timezone>=0):
    a="UTC+"+str(datetime.timedelta(seconds=time.timezone))
  return a
def handle(conn):
    print("1 register \n")
    data=input()
    #conn.write(b'GET / HTTP/1.1\n')
    conn.send(data.encode("utf-8"))
    while True:
        data1=conn.recv(1024)
        recv=data1.decode('utf-8')
        if (recv.startswith("Username")):
            print("username: ")
            data=getgpu()+" "+getUTC()+str(platform.architecture())+str(get_mac_address())
            data="username "+data
            conn.send(data.encode("utf-8"))
        elif (recv.startswith("Password")):
            data="123456"
            conn.send(data.encode("utf-8"))
        else:
            #data=input()
            #conn.send(data.encode("utf-8"))
            break
            #conn.close()
            #break
        #print(f"Received: {data1.decode('utf-8')}")
def main():
    
    sock = socket.socket(socket.AF_INET)

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.check_hostname = False
    context.verify_mode=ssl.CERT_NONE
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 
    conn = context.wrap_socket(sock, server_hostname=HOST)
    try:
        conn.connect((HOST, PORT))
        #conn.send("Hello World!".encode("utf-8"))
        handle(conn)
    finally:
        conn.close()
if __name__ == '__main__':
    main()