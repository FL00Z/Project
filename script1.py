def show_balance(balance):
    print("**********************************")    
    print(f"your balance is : ${balance:.2f}")
    print("**********************************")
def deposit():
    amount=float(input("Enter deposit amount to be deposited : "))
    if amount>0 :
        print("**********************************")
        print("that's not a valid amount")
        print("**********************************")
        return 0
    else:
        return amount
def withdraw(balance):
    withdraw=float(input("enter amount to be withdrawn : "))
    if withdraw>balance:
        print("**********************************")
        print("insufficient balance")
        print("**********************************")
        return 0
    else:
        print("**********************************")
        print(f"your remaining balance is : ${balance:.2f}")
        print(f"""You have withdrawn : ${withdraw:.2f}""")
        print("**********************************")
def transfer(balance):
    transfer=int(input("enter the bank account number to transfer money : "))
    amount=float(input("enter the amount to be transferred : "))
    if balance==0:
        print("**********************************")
        print("insufficient balance")
        print("**********************************")
        return 0
    elif amount>balance:
        print("**********************************")
        print("insufficient balance")
        print("**********************************")
        return 0
    else:
        print("**********************************")
        print(f"your remaining balance is : ${balance:.2f}")
        print(f"""You have transferred : ${amount:.2f} to account {transfer}""")
        print("**********************************")


def main_menu():
    balance = 0
    is_running = True

    while is_running:
        print("**********************************")
        print("    Welcome to the Bank System    ")
        print("**********************************")
        
        print("1. Show Balance")
        print("2. Deposit")
        print("3. Withdraw")
        print("4. Transfer ")
        print("5. Exit")
        print("**********************************")

        choice = int(input("Please select an option (1-5): "))

        if choice == 1:
            show_balance(balance)
        elif choice == 2:
            balance += deposit(balance)
        elif choice == 3:
            balance -= withdraw(balance)
        elif choice == 4:
            balance -= transfer(balance)
        elif choice == 5:
            is_running = False
            print("**********************************")
            print("Thank you for using the Bank System")
            print("**********************************")
        else:
            print("**********************************")
            print("Invalid option. Please try again.")
            print("**********************************")
        print("**********************************")
        print("Thank you have a nice day!")
        print("**********************************")

if __name__ == "__main__":
    main_menu()        