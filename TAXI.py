import numpy as np
import pandas as pd
from datetime import datetime
import time
import MySQLdb

counter = int()
array_of_count = []
start_time = time.time()

print("Импортирование библиотек успешно завершено... ✓")

conn = MySQLdb.connect(user='root', passwd='12345', db='test', 
          host='localhost', port=3306) 
print("Подключение к базе данных успешно завершено... ✓")
cursor = conn.cursor()

#data = pd.read_csv('C:\\Users\\Alex\\Desktop\\TAXI_NEW.csv',sep=';')
#flag_of_change = data.shape[0]
flag_of_change = cursor.rowcount
#array_of_count.append(0)

while(True):
    now = time.time()
    #now = datetime.strftime(datetime.now(), "%d.%m.%Y %H:%M")
    conn = MySQLdb.connect(user='root', passwd='12345', db='test', 
          host='localhost', port=3306)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM taxi")
    row = cursor.rowcount
    #data = pd.read_csv('C:\\Users\\Alex\\Desktop\\TAXI_NEW.csv',sep=';')
    
    if(row>flag_of_change):
        counter = counter+1
        flag_of_change = row
    if((now-start_time)>15):
        array_of_count.append(counter)
        counter = 0
        start_time = time.time()
        print(array_of_count)
        print(cursor.rowcount)
    
    #time.sleep(1)# пауза на 5 сек
#print(counter)