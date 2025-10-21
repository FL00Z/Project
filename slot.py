
import random


def spin():
    symbols=["🍒","🍉","🍋","🔔","⭐"]
    return [random.choice(symbols) for _ in range(3)]

def pay_out(row,bet):
    if row[0]==row[2]==row[1]:
        if row[0]=="⭐":
            return bet*5
        elif row[0]=="🔔":
            return bet*4
        elif row[0]=="🍋":
            return bet*3
        elif row[0]=="🍉":
            return bet*2
        elif row[0]=="🍒":
            return bet*1
    return 0

def print_row(row):
    print("------------------")
    print(" | ".join(row))
    print("------------------")
    return


def main():
    
    balance = 100
    print("*********************************************")
    print("  Welcome to the  Python Slot Machine!")
    print("        Symbols: 🍒🍉🍋🔔⭐                ")
    print("*********************************************")
    
    
    while balance>0:
        
        print(f"Your current balance is: ${balance}")
        bet = input("Enter your bet amount : ")
        
        if not bet.isdigit():
            print("Please enter a valid number for the bet amount.")
            continue
        bet = int(bet)
        
        if  bet>balance:
            print("Insufficient balance. Please enter a valid bet amount.")
            continue
        
        elif bet<=0:
            print("Bet amount must be greater than zero.")
            continue
        balance-=bet
        row = spin()
        print("spinning...\n")
        print_row(row)

        payout=pay_out(row,bet)
        if payout>0:
            print(f"Congratulations! You won ${payout}!")
            balance+=payout
        else:
            print("Sorry, you didn't win this time.")   

        balance+=payout

        play_again = input("Do you want to play again? (y/n): ").lower()
        if play_again != 'y':
            break    
    print("--------------------------------------------------------------")
    print(  f"Thank you for playing! Your final balance is: ${balance} ")
    print("--------------------------------------------------------------")

if __name__ == "__main__":
    main()

