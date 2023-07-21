import random

alphabet = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J",
 "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V",
 "W", "X", "Y", "Z"]

def give_code() -> str:
    gap_one = random.randint(1, 9)
    gap_two = random.randint(1, 9)
    gap_third = random.randint(1, 9)
    gap_four = alphabet[random.randint(0, 25)]
    gap_five = alphabet[random.randint(0, 25)]
    gap_six = alphabet[random.randint(0, 25)]
    code = f"{gap_one}{gap_two}{gap_third}{gap_four}{gap_five}{gap_six}"
    return code    