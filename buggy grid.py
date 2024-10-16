for snack in range(3):
    print(f"Getting snack {snack + 1}")
    hunger = 5
    while hunger > 0:
        print(f"  Still hungry... {hunger}")
        hunger += 1  # Bug: hunger increases instead of decreasing
