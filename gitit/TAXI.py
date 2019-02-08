import numpy as np
import pandas as pd
from datetime import datetime
import time
import MySQLdb

counter = int()
array_of_count = []#создание списка для заполнени значениями спроса (тестовый)

start_time = int(time.time())#время системы

print("Импортирование библиотек успешно завершено... ✓")

conn = MySQLdb.connect(user='root', passwd='Qweasded74', db='test', 
          host='localhost', port=3333) #подключение к базе данных 
print("Подключение к базе данных успешно завершено... ✓")
cursor = conn.cursor()
cursor.execute("SELECT * FROM new_table1")

flag_of_change = cursor.rowcount #получение количества строк таблицы 

while(True):
    now = int(time.time())
    cursor.execute("SELECT * FROM new_table1")
    row = cursor.rowcount
    conn.commit()
    if(row>flag_of_change):
        counter = counter+1
        flag_of_change = row
    if((now-start_time)>15):
        array_of_count.append(counter)
        cursor.execute("INSERT INTO `test`.`output` (`unix_time`,`count`) VALUES ('"+ str(now) + "','"+ str(counter) + "');")
        conn.commit()
        df = pd.read_sql('SELECT * FROM output', con=conn)
        counter = 0 
        start_time = int(time.time())
        #print(array_of_count)
        #print(cursor.rowcount)
        print(df)
    #time.sleep(1)# пауза на 5 сек