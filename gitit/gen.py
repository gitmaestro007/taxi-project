import MySQLdb
 
conn = MySQLdb.connect(user='root', passwd='Qweasded74', db='test', 
          host='localhost', port=3333)
#conn = MySQLdb.connect(user='root', passwd='12345', db='test', 
          #host='localhost', port=3306) 

cursor = conn.cursor()
 
cursor.execute("INSERT INTO `taxi` (`time`) VALUES ('6');")
 
# Получаем данные.
#row = cursor.rowcount
#print(row)
# Разрываем подключение.
conn.close()