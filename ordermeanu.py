meanu={"pizza": 10,
       "burger": 20,
       "pasta": 30,
       "sandwich": 40,
       "fries": 50,
       "coke": 60,
       "popcorn": 70
       }

cart=[]
total=0


print("---Welcome to the Food Ordering System---")
print()

print("--------Menu--------")
print()

for item, price in meanu.items():
    print(f"{item:10}: ${price:.2f}")
print("----------------------")


while True:
    item=input("Enter the item you want to order (or type 'q' to quit): ").lower()
    print()
    if item == 'q':
        break
    elif item in meanu:
        cart.append(item)
        total += meanu[item]
        
        print("---Items in your cart---")
        print()
        print(f"{item} added to cart. ")
        print("-------------------------")
    else:
        print("Item not found in menu. Please try again.")
print("--------TOTAL BILL-----")
print(f"Total: ${total:.2f}")
print("-----------------------")