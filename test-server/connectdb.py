import mysql.connector
import time
import hashlib
import test
import base64
y=6635057414239836812376941918868280148579585338800824299713832301121263657123
def hashsha3base64(input):
    digest1 = hashlib.sha3_256()
    digest1.update(input)
    digest2=base64.b64encode(digest1.digest())
    return digest2
def insertuser(id_u,y):
    mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  password="Tvhoang2012@gmail",
  database="tmis"
)
    mycursor = mydb.cursor()
    sql = "INSERT INTO user (hashname) VALUES (%s)"
    id_u=id_u+str(y)
    id_u=hashsha3base64(id_u.encode())
    val = (id_u,0)
    mycursor.execute(sql,(id_u,))
    mydb.commit()
    mycursor.close()
    mydb.close()
def insertserver(id_s):
    mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  password="Tvhoang2012@gmail",
  database="tmis"
)
    mycursor = mydb.cursor()
    sql = "INSERT INTO server (servername) VALUES (%s)"
    val = (id_s)
    mycursor.execute(sql, (val,))
    mydb.commit()
    mycursor.close()
    mydb.close()
def checkserverexit(id_s):
    mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  password="Tvhoang2012@gmail",
  database="tmis"
)
    mycursor = mydb.cursor()
    sql_select_query = """select servername from server where servername = %s""" 
    mycursor.execute(sql_select_query, (id_s,))
    myresult = mycursor.fetchall()
    mydb.commit()
    mycursor.close()
    mydb.close()
    return myresult
def checkuserexit(id_u,y):
    mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  password="Tvhoang2012@gmail",
  database="tmis"
)
    mycursor = mydb.cursor()
    id_u=id_u+str(y)
    id_u=hashsha3base64(id_u.encode())
    sql_select_query = """select hashname from user where hashname = %s""" 
    mycursor.execute(sql_select_query, (id_u,))
    myresult = mycursor.fetchall()
    mydb.commit()
    mycursor.close()
    mydb.close()
    return myresult
"""
def updatetime(id_u,time1):
    mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  password="Tvhoang2012@gmail",
  database="tmis"
)
    id_u=id_u+str(y)
    id_u=hashsha3base64(id_u.encode())
    mycursor = mydb.cursor()
    sql = "UPDATE user SET time = %s WHERE hashname = %s"
    val = (time1, id_u)
    mycursor.execute(sql, val)
    mydb.commit()
    mycursor.close()
    mydb.close()
"""
#insertuser("hoang1",y)
#a=checkuserexit("hoang",y)
#updatetime("hoang1")
#print(len(a))
