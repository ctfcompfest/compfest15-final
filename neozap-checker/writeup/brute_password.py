import hashlib
import itertools
from string import ascii_letters, digits
from datetime import datetime
import re


def generate_hash(input_string):
    sha384_hash = hashlib.sha384()
    sha384_hash.update(input_string.encode('utf-8'))
    return sha384_hash.hexdigest()


def brute(regexes, length=0):
    print(f"[*] Trying length: {length}")
    for combination in itertools.product(ascii_letters + digits, repeat=length):
        string = "".join(combination)
        sha384_hash = generate_hash(string)
        # print(sha384_hash)
        for regex in regexes:
            if re.match(regex, sha384_hash):
                print(
                    f"[{datetime.now().strftime('%H:%M:%S')}] Found: {string} {regex}")
                return sha384_hash

    return brute(regexes, length + 1)


print(f"[{datetime.now().strftime('%H:%M:%S')}] Starting brute force")
result = brute(["[a-f0-9]{88}dafa[a-f0-9]{4}"])
print(f"Result: {result}")
