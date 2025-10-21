import time
a=int(input("enter the number from which you want to countdown :  "))
for i in reversed(range(1,a)):
   seconds = i % 60
   minutes = int(i/60) % 60
   hours= int(i/3600)
   print(f"{hours:02}:{minutes:02}:{seconds:02}")
   time.sleep(1)

print("Times up !!")