from pickle import TRUE
import socket, ssl
from tracemalloc import stop
#from flask_login import ID_ATTRIBUTE
from matplotlib.pyplot import connect
import os
import time
from Crypto.PublicKey import ECC
from Crypto.Util.Padding import pad, unpad
from psutil import CONN_FIN_WAIT1
import scipy.io as sio
import hashlib
import numpy as np
from tkinter import *
import tkinter
import FuzzyExtractor_1_parallel
import encryptfile
HOST = '192.168.111.175'
n_p256=115792089210356248762697446949407573529996955224135760342422259061068512044369
gy=36134250956749795798585127919587881956611106672985015071877198253568414405109
gx=48439561293906451759052585252797914202762949526041747995844080717082404635286
def hashsha3(input):
  digest1 = hashlib.sha3_256()
  digest1.update(input)
  return digest1.digest()
def dangky(username_info,password_info):
    #username=input()
    username=username_info
    #passw=input()
    passw=password_info
    data = sio.loadmat("tests/test_files/140_1.mat")
    a1 = data['a']
    a1=np.array(a1).flatten()
    a1=FuzzyExtractor_1_parallel.arraytosbin(a1)
    fe = FuzzyExtractor_1_parallel.FuzzyExtractor()
    r, p = fe.gen(a1, locker_size=32, lockers=20000, confidence=None)
    FuzzyExtractor_1_parallel.savefile(p)
    r=bytes(r)
    rpw=passw+str(r)
    rpw=hashsha3(rpw.encode())
    rpw=int.from_bytes(rpw, byteorder="big")
    rec=username+","+str(rpw)
    return rec
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
    d_i=int.from_bytes(d_i, byteorder="big")
    return c_i,d_i
def onlineupdate(username, passw):
    c_i1,d_i=login(username,passw)
    f = open("filesave.txt", "r")
    line=f.readlines()
    c_i=int(line[1])
    f.close()
    if(c_i1!=c_i):
        return 0,0,0,0
    else:
        f = open("filesave.txt", "r")
        line=f.readlines()
        a_i=int(line[0])
        x=int(line[2])
        y=int(line[3])
        f.close()
        k_ui=a_i ^ d_i
        X=ECC.EccPoint(x=x,y=y,curve="p256")
        n=ECC.generate(curve='p256').d
        G=ECC.EccPoint(x=gx,y=gy,curve="p256")
        N=int(n)*G
        K=int(n)*X
        id=bytes(username, 'utf-8')
        id=pad(id,32)
        id = int.from_bytes(id, "big")
        DID=id^int(K.x)    
        return DID,N,K,k_ui
def registerfromrc(input):
    input=input.split(",")
    a_i=input[1]
    c_i=input[2]
    x=input[3]
    y=input[4]
    file = open("filesave.txt", "w")
    content=a_i+"\n"+c_i+"\n"+x+"\n"+y
    file.write(content)
    file.close()
def testupdate(input,id_u,k_ui,K):
    input=input.split(",")
    PK=ECC.EccPoint(x=int(input[1]),y=int(input[2])) 
    C_ij=ECC.EccPoint(x=int(input[3]),y=int(input[4]))
    v=int(input[5])
    v1=id_u+str(k_ui)+str(int(PK.x))+str(int(C_ij.x))+str(int(K.x))
    v1=hashsha3(v1.encode())
    v1=int.from_bytes(v1, byteorder="big")
    if(v!=v1):
        return None
    else:
        t_r=int(input[6])
        return PK,C_ij,t_r
def loginaka(username, passw):
    c_i1,d_i=login(username,passw)
    f = open("filesave.txt", "r")
    line=f.readlines()
    c_i=int(line[1])
    f.close()
    if(c_i1!=c_i):
        return 0,0,0,0,0,0,0,0
    else:
        f = open("filesave.txt", "r")
        line=f.readlines()
        a_i=int(line[0])
        f.close()
        k_ui=a_i ^ d_i
        f1=open("filesave1.txt", "r")
        line1=f1.readlines()
        id_s=line1[0]
        id_s=id_s.replace("\n","")
        pk_x=int(line1[1])
        pk_y=int(line1[2])
        c_ijx=int(line1[3])
        c_ijy=int(line1[4])
        t_r=int(line1[5])
        f1.close()
        n=ECC.generate(curve='p256').d
        t_u=int(time.time())
        G=ECC.EccPoint(x=gx,y=gy,curve="p256")
        PK=ECC.EccPoint(x=pk_x,y=pk_y,curve="p256")
        c_ij=ECC.EccPoint(x=c_ijx,y=c_ijy,curve="p256")
        W=int(n)*G
        q_u1=int(n)*PK
        q_u2=((int(n)*k_ui)%n_p256)*c_ij
        id=bytes(username, 'utf-8')
        id=pad(id,32)
        id = int.from_bytes(id, "big")
        DID=id^int(q_u1.x)
        v=str(username)+str(int(q_u1.x))+str(int(q_u2.x))+str(t_u)
        v=hashsha3(v.encode())
        v=int.from_bytes(v, "big")   
        return id_s,DID,W,v,t_u,t_r,q_u1,q_u2
def aka(recv,q_u1,q_u2,id_u,id_s,t_u):
    input=recv.split(",")
    ns_x=int(input[1])
    ns_y=int(input[2])
    t_s=int(input[3])
    v_s=int(input[4])
    t_u1=int(time.time())
    if(t_u1-t_s>30):
        return 0
    N_s=ECC.EccPoint(x=ns_x,y=ns_y,curve="p256")
    sk_ij=str(int(q_u1.x))+str(int(q_u2.x))+str(int(N_s.x))
    sk_ij=hashsha3(sk_ij.encode())
    sk_ij1=int.from_bytes(sk_ij, byteorder="big")
    v_s1=id_u+id_s+str(sk_ij1)+str(t_u)+str(t_s)
    v_s1=hashsha3(v_s1.encode())
    v_s1=int.from_bytes(v_s1, byteorder="big")
    if(v_s!=v_s1):
        return 0
    return sk_ij  
def handle(conn,username_info="hoang",password_info="hoang123@G"):
    #print("1 register \n")
    #data=input()
    data=dangky(username_info,password_info)
    a="userregister,"+str(data)
    #conn.write(b'GET / HTTP/1.1\n')
    conn.send(a.encode("utf-8"))
    while True:
        data1=conn.recv(1024)
        recv=data1.decode('utf-8')
        if (recv.startswith("OKDONE")):
            registerfromrc(recv)
            data="ok_register"
            conn.send(data.encode("utf-8"))
            print("registerok")
            conn.close()
            return "registerok"
            break
        else:
            print("userexit")
            conn.close()
            return "userexit"
            #data=input()
            #conn.send(data.encode("utf-8"))
            break
        #print(f"Received: {data1.decode('utf-8')}")
def handle1(conn,username,password,id_s):
    #print("1 register \n")
    #data=input()
    DID,N,K,k_ui=onlineupdate(username,password)
    if(DID==0):
        conn.close()
        print("wrong user")
        return "wrong_user"
    #id_s="23423545abc"
    a="onlineupdate,"+str(DID)+","+id_s+","+str(int(N.x))+","+str(int(N.y))
    #conn.write(b'GET / HTTP/1.1\n')
    conn.send(a.encode("utf-8"))
    while True:
        data1=conn.recv(1024)
        recv=data1.decode('utf-8')
        if (recv.startswith("OKUPDATEDONE")):
            PK,C_ij,t_r=testupdate(recv,username,k_ui,K)
            file = open("filesave1.txt", "w")
            content=str(id_s)+"\n"+str(PK.x)+"\n"+str(PK.y)+"\n"+str(C_ij.x)+"\n"+str(C_ij.y)+"\n"+str(t_r)
            file.write(content)
            file.close()
            data="ok_update"
            conn.send(data.encode("utf-8"))
            print("UPDATEDONE")
            conn.close()
            return "UPDATEDONE"
            break
        elif(recv.startswith("userdontexit")):
            #data=input()
            #conn.send(data.encode("utf-8"))
            print("userdontexit")
            conn.close()
            return "userdontexit"
            break
        else:
            conn.close()
            return "userdontexit"
            break
def handle2(conn,username="hoang",password="hoang123@G"):
    #print("1 register \n")
    #data=input()
    id_u=username
    id_s,DID,W,v,t_u,t_r,q_u1,q_u2=loginaka(username,password)
    if(DID==0):
        conn.close()
        print("wrong_user")
        return "wrong_user"
    a="loginandaka,"+str(id_s)+","+str(DID)+","+str(int(W.x))+","+str(int(W.y))+","+str(v)+","+str(t_u)+","+str(t_r)
    #conn.write(b'GET / HTTP/1.1\n')
    conn.send(a.encode("utf-8"))
    sk_ij=0
    while True:
        if(sk_ij==0):
            data1=conn.recv(1024)
            recv=data1.decode('utf-8')
            if (recv.startswith("authenticationdone")):
                sk_ij=aka(recv,q_u1,q_u2,id_u,id_s,t_u)
                if(sk_ij==0):
                    conn.close()
                    break
            else:
                conn.close()
                break
        elif(sk_ij!=0):
            send_encrypt(conn,sk_ij)
        else:
            conn.close()
            break
def send_encrypt(conn,sk_ij):
    global send_screen
    send_screen = Toplevel(login_screen)
    send_screen.title("send")
    send_screen.geometry("300x250")
    Label(send_screen, text="send").pack()
    Label(send_screen, text="").pack()
    global send_verify
    global conn1
    global sk_ij1
    conn1=conn
    sk_ij1=sk_ij
    send_verify = StringVar()
    global send_login_entry
    Label(send_screen, text="send * ").pack()
    send_login_entry = Entry(send_screen, textvariable=send_verify)
    send_login_entry.pack()
    Label(send_screen, text="").pack()
    Button(send_screen, text="send", width=10, height=1, command = send_text).pack()
    send_screen.mainloop() 
def send_text():
    send_info=send_verify.get()
    send=bytes(send_info, 'utf-8')
    send=encryptfile.encryptplaintext(send,sk_ij1)
    conn1.send(send)
    global data
    data=conn1.recv(1024)
    data=encryptfile.decryptcipher(data,sk_ij1)
    data=data.decode("utf-8")
    delete_send_screen()
    #global label
    #label=Label(send_screen, text=data, fg="green", font=("calibri", 11)).pack()
    #Button(send_screen, text="OK", command=delete_send_screen).pack()
def delete_send_screen():
    global login_success_screen
    login_success_screen = Toplevel(send_screen)
    login_success_screen.title("From-sever")
    login_success_screen.geometry("300x250")
    Label(login_success_screen, text=data).pack()
    Button(login_success_screen, text="OK", command=delete_login_success).pack() 
def delete_login_success():
    login_success_screen.destroy()
def main():
    #compute_psid()
    value = input()
    if(value.startswith("register")):
        PORT=4455
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect((HOST, PORT))
        #conn.send("Hello World!".encode("utf-8"))
                handle(s)
            finally:
                s.close()
    elif(value.startswith("update")):
        PORT=4455
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect((HOST, PORT))
        #conn.send("Hello World!".encode("utf-8"))
                handle1(s)
            finally:
                s.close()
    elif(value.startswith("login")):
        PORT=4456
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect((HOST, PORT))
        #conn.send("Hello World!".encode("utf-8"))
                handle2(s)
            finally:
                s.close()
def register_user():
    username_info = username.get()
    password_info = password.get()
    PORT=4455
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((HOST, PORT))
        #conn.send("Hello World!".encode("utf-8"))
            test=handle(s,username_info,password_info)
        finally:
            s.close()
    if(test=="registerok"):
        Label(register_screen, text="Registration Success", fg="green", font=("calibri", 11)).pack()
    elif(test=="userexit"):
        Label(register_screen, text="Registration Failed", fg="green", font=("calibri", 11)).pack()
def on_lineupdate_user():
    username_info = username.get()
    password_info = password.get()
    id_s1=id_s.get()
    PORT=4455
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((HOST, PORT))
        #conn.send("Hello World!".encode("utf-8"))
            test=handle1(s,username_info,password_info,id_s1)
        finally:
            s.close()
    if(test=="UPDATEDONE"):
        Label(online_screen, text="Success", fg="green", font=("calibri", 11)).pack()
    else:
        Label(online_screen, text="Failed", fg="green", font=("calibri", 11)).pack()
def login_user():
    username_info = username.get()
    password_info = password.get()
    PORT=4456
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((HOST, PORT))
        #conn.send("Hello World!".encode("utf-8"))
            test=handle2(s,username_info,password_info)
        finally:
            s.close()
    if(test=="wrong_user"):
        Label(login_screen, text="Failed", fg="green", font=("calibri", 11)).pack()
def register():
    global register_screen
    register_screen = Toplevel(main_screen)
    register_screen.title("Register")
    register_screen.geometry("300x250")
    global username
    global password
    global username_entry
    global password_entry
    username = StringVar()
    password = StringVar()
    Label(register_screen, text="Please enter details below", bg="blue").pack()
    Label(register_screen, text="").pack()
    username_lable = Label(register_screen, text="Username * ")
    username_lable.pack()
    username_entry = Entry(register_screen, textvariable=username)
    username_entry.pack()
    password_lable = Label(register_screen, text="Password * ")
    password_lable.pack()
    password_entry = Entry(register_screen, textvariable=password, show='*')
    password_entry.pack()
    Label(register_screen, text="").pack()
    Button(register_screen, text="Register", width=10, height=1, bg="blue", command = register_user).pack()
def on_lineupdate():
    global online_screen
    online_screen = Toplevel(main_screen)
    online_screen.title("Online-update")
    online_screen.geometry("300x250")
    global username
    global password
    global id_s
    global username_entry
    global password_entry
    global id_s_entry
    username = StringVar()
    password = StringVar()
    id_s=StringVar()
    Label(online_screen, text="Please enter details below", bg="blue").pack()
    Label(online_screen, text="").pack()
    username_lable = Label(online_screen, text="Username * ")
    username_lable.pack()
    username_entry = Entry(online_screen, textvariable=username)
    username_entry.pack()
    password_lable = Label(online_screen, text="Password * ")
    password_lable.pack()
    password_entry = Entry(online_screen, textvariable=password, show='*')
    password_entry.pack()
    online_lable = Label(online_screen, text="id_s * ")
    online_lable.pack()
    id_s_entry = Entry(online_screen, textvariable=id_s)
    id_s_entry.pack()
    Label(online_screen, text="").pack()
    Button(online_screen, text="Online-udate", width=10, height=1, bg="blue", command = on_lineupdate_user).pack()
def login_1():
    global login_screen
    login_screen = Toplevel(main_screen)
    login_screen.title("login")
    login_screen.geometry("300x250")
    global username
    global password
    global username_entry
    global password_entry
    username = StringVar()
    password = StringVar()
    Label(login_screen, text="Please enter details below", bg="blue").pack()
    Label(login_screen, text="").pack()
    username_lable = Label(login_screen, text="Username * ")
    username_lable.pack()
    username_entry = Entry(login_screen, textvariable=username)
    username_entry.pack()
    password_lable = Label(login_screen, text="Password * ")
    password_lable.pack()
    password_entry = Entry(login_screen, textvariable=password, show='*')
    password_entry.pack()
    Label(login_screen, text="").pack()
    Button(login_screen, text="Login", width=10, height=1, bg="blue", command = login_user).pack()
def main_account_screen():
    #hoang
    #hoang123@G
    #23423545abc
    global main_screen
    main_screen = Tk()
    main_screen.geometry("300x250")
    main_screen.title("Account Login")
    Label(text="Select Your Choice", bg="blue", width="300", height="2", font=("Calibri", 13)).pack()
    Label(text="").pack()
    Button(text="Login", height="2", width="30", command = login_1).pack()
    Label(text="").pack()
    Button(text="On-line update", height="2", width="30", command=on_lineupdate).pack()
    Label(text="").pack()
    Button(text="Register", height="2", width="30", command=register).pack()
    main_screen.mainloop()
if __name__ == '__main__':
    #main()
    try:
        main_account_screen()
    except:
        None