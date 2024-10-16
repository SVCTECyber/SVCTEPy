num_laptops = 7
laptop_cost = 1099.50
price = num_laptops * laptop_cost
print("Total cost of laptops:", price)

print("Total cost of laptops: $", format(price,'.2f'))
print("Total cost of laptops:", format(price,'.2f'))

print(f"Total cost of laptops: {price:.2f}")

print(f"Total cost of laptops: $ {price:.2f}")

laptop_cost = 1100
price = int(price)
print("Total cost of laptops:", format(price,'2d'))
print("Total cost of laptops:", format(price,'10d'))
