name=input("Enter the name : ")
if len(name)<3:
    print("name must be at least 3 character long")
elif len(name)>50:
    print("name can be max be 50 character")
else:
    print("name looks good")
