a=str(input("enter a string:  "))
if a.isdigit():
    print("enter alpahabets only")
elif " " in a:
    print("enter without space")
elif len(a)>12:
    print("enter less than 12 characters")
else:
    print("valid string: ")
