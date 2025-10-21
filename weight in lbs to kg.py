weight=input("Enter the weight: ")
unit=input("(L)Lbs or (K)Kg :")
if unit.upper()== "K":
    z=2.22*float(weight)
elif unit.upper()== "L"  :
    z=0.45*float(weight)
else :
    print("Enter the valid value")
print(f"your weight is : {z}")    
