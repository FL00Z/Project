shape = input(
    "Enter the shape you want to draw:\n"
    "For rectangle type r:\n"
    "For square type s:\n"
    "For triangle type t:\n"
    "For pyramid type p:\n"
    "For diamond type d:\n"
)

 
if shape=="r":
    a=int(input("enter the number of rows :  "))
    b=int(input("enter the number of columns :  "))
    symbol=input("enter the symbol : ")
    for i in range(a):
        for j in range(b):
            print(symbol,end="")
        print()

elif shape =="s" :
    a=int(input("enter the number of rows :  "))
    symbol=input("enter the symbol : ")
    for i in range(a):
        for j in range(a):
            print(symbol,end="")
        print()

elif shape == "t":
    a=int(input("enter the number of rows :  "))
    b=int(input("enter the number of columns :  "))
    symbol=input("enter the symbol : ") 
    for i in range(a):
        for j in range(i+1):
            print(symbol,end="")
        print()

elif shape == "p":
    a=int(input("enter the number of rows :  "))
    symbol=input("enter the symbol : ")
    for i in range(a):
        for j in range(a-i-1):
            print(" ",end="")
        for k in range(2*i+1):
            print(symbol,end="")
        print()

elif shape == "d":
    a=int(input("enter the number of rows :  "))
    symbol=input("enter the symbol : ")
    for i in range(a):
        for j in range(a-i-1):
            print(" ",end="")
        for k in range(2*i+1):
            print(symbol,end="")
        print()
    for i in range(a-1):
        for j in range(i+1):
            print(" ",end="")
        for k in range(2*(a-i-1)-1):
            print(symbol,end="")
        print()
else:
    print("invalid input")