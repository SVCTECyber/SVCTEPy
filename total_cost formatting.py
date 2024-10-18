
item_name = input("Enter the name of the item: ")
num_items = int(input("Enter the number of items: "))
item_cost = float(input("Enter the cost of one item: "))

#Calculating price
total_cost = num_items * item_cost

#Printing results
print("Item name : ", item_name)
print("Cost of one item: ", item_cost)
print("Number of items purchased: ", num_items)
print(f"Total cost: {total_cost:.2f}")

print("Total cost: $", format (total_cost , "0.2f"), sep= ' ')

price = 1500
print(f"Total cost of laptops: {price:2d}")
print(f"Total cost of laptops: {price:10d}")
print(f"Total cost of laptops: {price}")