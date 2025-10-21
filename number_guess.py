import random
is_running= True
guesses=0

print("-----------------------------------")
print("Welcome to the Number Guessing Game!")
print("-----------------------------------\n")


lower=int(input("enter the lower limit of the range:  "))
upper=int(input("enter the upper limit of the range:  "))
print()


number=random.randint(lower,upper)


while is_running:
    guess=input(f"Guess a number between {lower} and {upper}: ")
    
    if guess.isdigit():
        guess=int(guess)
        guesses+=1
        
        
        if guess < lower or guess > upper:
            print()
            print("YOUR GUESS IS OUT OF RANGE!\n")
            print(f"Guess a number between {lower} and {upper}.\n")

        elif guess > number:
            print("TOO HIGH! TRY AGAIN.\n")
        elif guess < number:
            print("TOO LOW! TRY AGAIN.\n")
        else:
            print("************************************")
            print(f"CONGRATULATIONS! YOU'VE GUESSED THE NUMBER {number} IN {guesses} ATTEMPTS.")
            print("************************************")
            is_running=False
    else:
        print()
        print(f"PLEASE ENTER A VALID NUMBER BETWEEN {lower} AND {upper}: \n")
