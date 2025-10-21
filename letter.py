import random
print("welcome to Hangman")
words=["car","bus","bike","aeroplane","heli","ship"]
secret_word=random.choice(words)
b=[" _ "]*len(secret_word)
print(b)
             

