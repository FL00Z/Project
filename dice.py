import random
dice_art = {1: ["┌───────┐", 
                "│       │", 
                "│   ●   │", 
                "│       │", 
                "└───────┘"],
            
            2:  ["┌───────┐", 
                 "│       │", 
                 "│●     ●│", 
                 "│       │", 
                 "└───────┘"],
                 
            3:  ["┌───────┐", 
                 "│   ●   │", 
                 "│   ●   │", 
                 "│   ●   │", 
                 "└───────┘"],

             4:  ["┌───────┐", 
                  "│●     ●│", 
                  "│       │", 
                  "│●     ●│", 
                  "└───────┘"],

            5:  ["┌───────┐", 
                 "│●     ●│", 
                 "│   ●   │", 
                 "│●     ●│", 
                 "└───────┘"],
            
            6:  ["┌───────┐", 
                 "│●     ●│", 
                 "│●     ●│", 
                 "│●     ●│", 
                 "└───────┘"]}

dice=[]
total=0

print("-----------------------------------\n")
print("Welcome to the Dice Rolling Simulator!\n")
print("-----------------------------------\n")

numberofdice=int(input("Enter the number of dice you want to roll: "))


for die in range(numberofdice):
    dice.append(random.randint(1,6))
    
for line in range(5):
    for die in dice:
        print(dice_art[die][line], end=" ")
    print()

for die in range (numberofdice):
    total+=dice[die]

print("***********")
print(f"Total: {total}")
print("***********")