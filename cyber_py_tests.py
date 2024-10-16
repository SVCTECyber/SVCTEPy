brought_food = True
print("Brought food? " + str(brought_food))
print(f"Brought food? {brought_food}")

is_awake = "True"
is_studying = "False"
if is_awake and is_studying:
    print("Procrastination mode: ON")

print(bool(is_awake))
print(bool(is_studying))

is_studying = ""
print(bool(is_studying))

song_1 = "Blinding Lights"
song_2 = "Levitating"
if song_1 > song_2:
    print(f"{song_1} plays first.")
else:
    print(f"{song_2} plays first.")
