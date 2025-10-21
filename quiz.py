question=("What is the capital of India?: ",
           "How many continents are there on Earth?:  ",
           "what is the largest animal in the world: ",
           "How many state are there in India?: ",
           "how many colors are there in the rainbow?: ")


options=(("a. Mumbai", "b. New Delhi", "c. Kolkata", "d. Chennai"),
         ("a. 5", "b. 6", "c. 7", "d. 8"),
         ("a. Elephant", "b. Blue Whale", "c. Great White Shark", "d. Giraffe"),
         ("a. 28", "b. 29", "c. 30", "d. 31"),
         ("a. 5", "b. 6", "c. 7", "d. 8"))


answers=("b", "d", "b", "a", "c")
guesses=[]
score=0
question_num=0



while question_num < len(question):
    print("-------------------------")
    print(question[question_num])
    for option in options[question_num]:
        print(option)
    
    guess = input("Enter your answer (a/b/c/d): ").lower()
    guesses.append(guess)
    if guess == answers[question_num]:
        print("Correct!")
        score += 1
    else:
        print("Incorrect.")
    question_num += 1


print("-------------------------")
print( "         RESULTS        ")
print("-------------------------")


print("Answers: ", end="")
for answer in answers:
    print(answer, end=" ")
print()


print("Guesses: ", end="")
for guess in guesses:
    print(guess, end=" ")
print()

score= int(score / len(question) * 100)
print(f"your score is: {score}%")