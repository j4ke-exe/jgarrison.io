---
title: "GME Tracker"
datePublished: Fri Aug 04 2023 06:56:26 GMT+0000 (Coordinated Universal Time)
cuid: clkw8fu30000h09mmedrb9n79
slug: gme-tracker
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1691132113525/f4948156-0593-47b6-b77b-678baf6a4a6d.jpeg
tags: python, stockmarket, technical-analysis, gme, gamestop

---

%[http://github.com/wayahlife/GME-Tracker] 

<div data-node-type="callout">
<div data-node-type="callout-emoji">❗</div>
<div data-node-type="callout-text">Disclaimer: I am not a financial advisor. None of this is financial advice.</div>
</div>

### What is GME-Tracker?

A lightweight, easy-to-use, all-in-one program that displays everything a GME investor would need.

### Dependencies

* Python 3.x
    
* pip
    

### Known Issues

Might need to install `mpl_finance` and `Matplotlib` directly.

1. `pip install` [`https://github.com/matplotlib/mpl_finance/archive/master.zip`](https://github.com/matplotlib/mpl_finance/archive/master.zip)
    
2. `python -m pip install -U matplotlib`
    

### Installing

Easy 3-step process:

1. `git clone` [`https://github.com/wayahlife/GME-Tracker.git`](https://github.com/wayahlife/GME-Tracker.git)
    
2. `cd GME-Tracker`
    
3. `pip install -r requirements.txt`
    

### Syntax

* `python3` [`main.py`](http://main.py)
    

### Program Overview

Menu:

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691131920934/5e84aba1-4cd5-4a31-92dd-860feb32389d.png align="center")

```python
import os
import time
import ctypes
import subprocess
import webbrowser
import yfinance as yf
import mplfinance as mpf
import matplotlib.pyplot as plt
from pyfiglet import Figlet

def get_current_price():
    # Get the current price of the stock
    os.system("start python3 price.py")
    os.system("python3 main.py")

def get_historical_data():
    # Get the historical data for the stock
    os.system("start python3 historical.py")
    os.system("python3 main.py")

def plot_historical_data():
    # Get the historical data for the stock
    data = gme.history(period="1y")

    # Plot the data
    mpf.plot(data, type="candle", style="charles", volume=True, title="GameStop (GME)")

    # Show the plot
    plt.show()
    os.system("python3 main.py")

def open_dd_library():
    # Open the DD library in a new window
    webbrowser.open("http://www.gme.fyi")
    os.system("python3 main.py")

def open_subreddit():
    # Open the subreddit in a new window
    webbrowser.open("https://www.reddit.com/r/Superstonk/")
    os.system("python3 main.py")

# Resize the terminal window
if os.name == "posix":
    subprocess.run(['resize', '-s', '22', '43'])
elif os.name == "nt":
    os.system("mode con: cols=43 lines=22")

# Rename terminal window
ctypes.windll.kernel32.SetConsoleTitleW("Power to the Players")

# Banner
custom_fig = Figlet(font='isometric1')
asci_banner = custom_fig.renderText("GME")

# Print the banner to the console
print(asci_banner + ("-" * 43) + "\n")

# Get the stock data for GameStop
gme = yf.Ticker("GME")

# Option Menu
print("1. Get the current price of GME.")
print("2. Get the historical data of GME.")
print("3. Plot the historical data of GME.")
print("4. View the GME DD library.")
print("5. Visit HQ r/Superstonk.")
print("6. Exit\n")

# Get the user's choice
choice = int(input("Enter your choice: "))

# Handle the user's choice
try:
    if choice == 1:
        get_current_price()
    elif choice == 2:
        get_historical_data()
    elif choice == 3:
        plot_historical_data()
    elif choice == 4:
        open_dd_library()
    elif choice == 5:
        open_subreddit()
    elif choice == 6:
        # Exit the program
        print("""\n
        Hedgies R' Fuk.
        
        Ken Griffin lied under oath.
        
        DTCC committed international 
        securities fraud.
        
        DRS your shares!\n""")
        time.sleep(5)
    os.system("cls")
    exit()

except (KeyboardInterrupt, SystemExit, ValueError, TypeError):
    exit()
```

Price Feed:

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691132004092/7eb71d6d-c523-46b0-a324-f6dedb898169.png align="center")

```python
import os
import ctypes
import yfinance as yf

# Resize the terminal window
if os.name == "nt":
    # Windows
    os.system("mode con: cols=35 lines=15")

# Rename terminal window
ctypes.windll.kernel32.SetConsoleTitleW("GME Price - [Live]")

gme = yf.Ticker("GME")

try:
    while True:
        info = gme.info
        price = info["regularMarketPrice"]
        print(f"The current price of GME is ${price}")
except KeyboardInterrupt:
    print("Exiting...")
```

Historical Data:

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691132020998/08e4ca5c-ed5b-40e7-80b5-b16ec6d2b8cc.png align="center")

```python
import os
import time
import ctypes
import yfinance as yf

# Resize the terminal window
if os.name == "nt":
    # Windows
    os.system("mode con: cols=77 lines=15")

# Rename terminal window
ctypes.windll.kernel32.SetConsoleTitleW("GME Historical Data - [1 Year]")

gme = yf.Ticker("GME")

# Get the historical data for the stock
data = gme.history(period="1y")
print(data)

# Keep window open
time.sleep(5000)
```

Plot Data:

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1691132043722/0acd610e-ce1d-4b4f-a73e-fc39a911f8cd.png align="center")