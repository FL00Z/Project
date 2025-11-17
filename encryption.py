import string
import random
import getpass


chars = " "+string.ascii_letters+string.digits+string.punctuation
chars =list(chars)
key =chars.copy()
random.shuffle(key)

plaintext = input("enter the text to be encrypted : ")
ciphertext =""
print("****************************************************************************")
password = getpass.getpass("enter the password that is going to be used for decryption :  ")
print("****************************************************************************")

#Encryption
for letter in plaintext :
    index = chars.index(letter)
    ciphertext += key[index]
print(f"original text: {plaintext}")
print("-----------------------------")
print(f"encrypted text: {ciphertext}")
print("-----------------------------")

#Decryption
approval = input("do you want to proceed to decryption? (y/n) : ")
if approval.lower() == "y":
    
    
    while True:
        password_check = input("enter the password for decryption : ")
        if password_check != password:
            print("Incorrect password! Please enter the correct password.")
            try_again = input("Do you want to try again? (y/n): ").lower()
            if try_again != "y":
                print("Exiting decryption...")
                break
        
        
        else:
            ciphertext = input("enter the text to be decrypted : ")
            plaintext = ""
            for letter in ciphertext :
                index = key.index(letter)
                plaintext += chars[index]
            print(f"original text: {plaintext}")
            print("-----------------------------")
            print(f"encrypted text: {ciphertext}")
            print("-----------------------------")
            
            break

