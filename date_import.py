import datetime 
date=datetime.date(2025,1,2)
today=datetime.date.today()

time=datetime.time(12,30,0)
now=datetime.datetime.now()
now=now.strftime("%H:%M:%S %d-%m-%Y")

print(date)
print(today)
print(time)
print(now)