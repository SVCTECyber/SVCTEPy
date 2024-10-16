

for hour in range(1, 4):  # Simulate checking the battery over 3 hours
    print(f"Hour {hour}: Checking battery...")
    battery = 50  # Start at 50% battery every hour
    while battery < 100:
        battery += 10  # Charging the battery by 10% at a time
        print(f"  Charging... Battery at {battery}%")


