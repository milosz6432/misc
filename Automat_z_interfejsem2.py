import tkinter as tk
from tkinter import messagebox
import random
import threading
import time

# --- Konfiguracja gry ---
symbols = ["🍒", "🍋", "🍉", "💎", "⭐"]
symbol_rewards = {
    "🍒": 20,
    "🍋": 30,
    "🍉": 40,
    "💎": 200,
    "⭐": 100
}

balance = 50
highest_balance = balance  # przechowuje najwyższy balans
debt_used = False

# --- Funkcje gry ---
def spin():
    global balance, debt_used, highest_balance

    if balance < 5:
        result_label.config(text="💸 Masz za mało pieniędzy!")
        if not debt_used:
            if messagebox.askyesno("Zadłużenie", "Czy chcesz zadłużyć swoją rodzinę na 100 $?"):
                balance += 100
                debt_used = True
                # aktualizacja highest_balance po zadłużeniu
                if balance > highest_balance:
                    highest_balance = balance
                    highest_label.config(text=f"Highest: {highest_balance} $")
                update_balance()
            else:
                end_game()
        else:
            result_label.config(text="Nie możesz już więcej się zadłużyć!")
            end_game()
        return

    balance -= 5
    update_balance()

    threading.Thread(target=animate_spin).start()

def animate_spin():
    global balance, highest_balance

    for _ in range(15):
        reels = [random.choice(symbols) for _ in range(3)]
        reel_labels[0].config(text=reels[0])
        reel_labels[1].config(text=reels[1])
        reel_labels[2].config(text=reels[2])
        time.sleep(0.1)

    a, b, c = [random.choice(symbols) for _ in range(3)]
    reel_labels[0].config(text=a)
    reel_labels[1].config(text=b)
    reel_labels[2].config(text=c)

    if a == b == c:
        reward = symbol_rewards.get(a, 50)
        result_label.config(text=f"🎉 Jackpot {a*3}! Wygrana: {reward} $")
        balance += reward
    else:
        result_label.config(text="❌ Spróbuj ponownie!")

    # aktualizacja highest balance
    if balance > highest_balance:
        highest_balance = balance
        highest_label.config(text=f"Highest: {highest_balance} $")

    update_balance()

def update_balance():
    balance_label.config(text=f"Balans: {balance} $")

def end_game():
    messagebox.showinfo("Koniec gry", f"Koniec gry! Twój końcowy balans: {balance} $\nNajwyższy balans: {highest_balance} $")
    root.quit()

# --- Interfejs gry ---
root = tk.Tk()
root.title("Slot Machine 🎰")
root.geometry("400x300")

balance_label = tk.Label(root, text=f"Balans: {balance} $", font=("Arial", 14))
balance_label.pack(pady=10)

# Highest balance w rogu
highest_label = tk.Label(root, text=f"Highest: {highest_balance} $", font=("Arial", 10))
highest_label.place(x=300, y=10)  # pozycja w prawym górnym rogu

frame = tk.Frame(root)
frame.pack(pady=20)

reel_labels = [
    tk.Label(frame, text="❓", font=("Arial", 40)),
    tk.Label(frame, text="❓", font=("Arial", 40)),
    tk.Label(frame, text="❓", font=("Arial", 40)),
]

for lbl in reel_labels:
    lbl.pack(side="left", padx=10)

result_label = tk.Label(root, text="Kliknij SPIN aby zagrać", font=("Arial", 12))
result_label.pack(pady=10)

spin_button = tk.Button(root, text="SPIN 🎰", font=("Arial", 16), command=spin)
spin_button.pack(pady=10)

root.mainloop()
