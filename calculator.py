operator=input("enter the operator (+,-,*,/) :  ")
a=float(input("enter the first number :"))
b=float(input("enter the second number :"))

if operator == "+":
    print(a+b)
elif operator== "-":
    print(a-b)
elif operator == "*":
    print(a*b) 
elif operator =="/":
    print(a/b)
else:
    print("enter the given operator only")
