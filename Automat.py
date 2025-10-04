import random

balance = 50  
symbols = ["🍒", "🍋", "🍉", "💎", "⭐"]  
debt_used = False  

while True:
    balance -= 5
    print(f"\nTwoj balans: {balance} $")

    # gambling
    a = random.choice(symbols)
    b = random.choice(symbols)
    c = random.choice(symbols)
    print(a, b, c)

    # sprawdzanie wyniku
    if a == b == c:
        print("🎉 Jackpot!!!!!!!!!!")
        balance += 50
        print(f"Nowy balans: {balance} $")
    else:
        print("Gamble again")

    # sprawdzenie, czy masz kasę na dalszą grę
    if balance < 5:
        print("Masz za mało pieniędzy, żeby grać dalej!")

        if not debt_used:  
            debt_choice = input("Czy chcesz zadluzyc swoją rodzinę? (y/n): ")
            if debt_choice.lower() == "y":
                balance += 100
                debt_used = True
                print("Zadłużyłeś swoją rodzinę! +100 $ na koncie.")
                continue
            else:
                print(f"Koniec gry. Twój końcowy balans: {balance} $")
                break
        else:
            print("Nie możesz już ponownie zadłużyć rodziny! 😨 Mam nadzieję, że było warto")
            print(f"Koniec gry. Twój końcowy balans: {balance} $")
            break

    answer = input("Care to try again? (5 dollar) Type: y/n ")
    if answer.lower() != "y":
        print(f"Koniec gry. Twój końcowy balans: {balance} $")
        break
