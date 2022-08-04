from pickle import TRUE
import socket, ssl
import time
import datetime
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
context.load_cert_chain(certfile="mycert.pem") 

def handle(conn):
  while True:
    #conn.write(b'GET / HTTP/1.1\n')
    data=conn.recv(1024)
    recv=data.decode('utf-8')
    if (recv=="1"):
        a="Username"
        conn.sendall(a.encode("utf-8"))
        print(f"Received: {data.decode('utf-8')}")
    elif(recv.startswith("username")==True):
        a="Password"
        conn.sendall(a.encode("utf-8"))
        print(f"Received: {data.decode('utf-8')}")
    else:
        a="bcd"
        conn.sendall(a.encode("utf-8"))
        print(f"Received: {data.decode('utf-8')}")
        time.sleep(3)
        break
while True:
  sock = socket.socket()
  sock.bind(('192.168.111.129', 443))
  sock.listen(5)
  context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
  context.load_cert_chain(certfile="mycert.pem") 
  context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # optional
  context.set_ciphers('AES256+ECDH:AES256+EDH')
  conn = None
  ssock, addr = sock.accept()
  try:
      conn = context.wrap_socket(ssock, server_side=True)
      #data = ssock.recv(1024)
      #print(data.decode('utf-8'))
      handle(conn)
  except ssl.SSLError as e:
    print(e)
  finally:
      if conn:
        sock.close()
        conn.close()
