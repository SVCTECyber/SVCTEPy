messages = 0
while True:
    messages += 1
    if messages == 4:
        print("Okay, I need to stop texting!")
        continue
    if messages >= 15:
        print("Okay, I REALLY need to stop texting!")
        break
    print(f"Sending message {messages}...")
