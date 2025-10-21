def week_day(day) :
    match  day :
        case 1 :
            return "monday"
        case 2 :
            return "tuesday"
        case 3 :
            return "wednesday"
        case 4 :
            return "thursday"
        case 5 :
            return "friday"
        case 6 :
            return "saturday"
        case 7 :
            return "sunday"
        case _ :
            return "invalid day"

def week_end(day) :
    match day:
        case "monday" | "tuesday" | "wednesday" | "thursday" | "friday":
            return "week day"
        case "saturday" | "sunday":
            return "weekend"
        case _:
            return "invalid day"

print("******************************************************************************************************************")
function = int(input("enter  the  function you want to use (week_day / week_end) :  1 for week_day , 2 for week_end : "))
print("******************************************************************************************************************\n")


if function ==1 :
    day =input("enter day number 1 to 7 : ")
    print(week_day(int(day)))
elif function ==2 :
    day = input("enter day name  to check if it is week day or weekend : ")    
    print(week_end(day))
else :
    print("the the valid function number")