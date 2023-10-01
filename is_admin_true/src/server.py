from hashlib import sha256
import random
import os

p = 69278042787891942769502075928585090381290090384778024990006411012262963663859
g = 2
m = 4267738774321166375026693303590202006447685928119906506624384544530089122661922193
a = 1872159875735606573086019350365709191427276692069413859597107145760799047673904037
c = 3852523496907343703707599716820831623137858734069135383774172801943851091960152572

class LCG:
    def __init__(self, m,a,c, seed):
        self.m = m
        self.a = a
        self.c = c
        self.state = seed

    def next(self):
        self.state = (self.a * self.state + self.c) % self.m
        return self.state >> 16

class TokenGenerator:
    def __init__(self, p,g,m,a,c):
        self.p = p
        self.g = g
        self.x = random.randint(1,p)
        self.lcg = LCG(m,a,c, random.randint(1, m))

    def next(self):
        k = self.lcg.next()
        self.x = pow(self.g, k, self.p) * self.x % self.p
        return self.x

class Server:
    def __init__(self):
        self.users = {}
        self.sessions = {}
        self.token_generator = TokenGenerator(p,g,m,a,c)
        self.user = None

    def generate_token(self):
        x = self.token_generator.next()
        return hex(x)

    def register(self, username, password, is_admin=False):
        if username in self.users:
            print("[x] Username already exists")
            return
        token = self.generate_token()
        self.sessions[token] = username
        self.users[username] = {
            "username": username,
            "password": sha256(password.encode()).hexdigest(),
            "token": token,
            "is_admin": is_admin,
        }
        return token

    def get_token(self, username, password):
        if username not in self.users:
            print("[x] Invalid username")
            return
        if self.users[username]["password"] != sha256(password.encode()).hexdigest():
            print("[x] Invalid password")
            return

        token = self.generate_token()
        self.sessions[token] = username
        self.users[username]["token"] = token
        return token

    def set_token(self, token):
        if token not in self.sessions:
            print("[x] Invalid token")
            return
        self.user = self.users[self.sessions[token]]
        print("Welcome, " + self.user["username"])

    def get_flag(self):
        if self.user is None:
            print("You must login first")
            return
        if not self.user["is_admin"] == True: # <-- is_admin=true??
            print("Only admin can access the flag")
            return
        
        print(open("/flag/flag.txt").read())

print("=" * 100)
print(f"p = {p}")
print(f"g = {g}")
print(f"m = {m}")
print(f"a = {a}")
print(f"c = {c}")
print("=" * 100)

server = Server()
server.register("admin", os.getenv("PASSWORD"), True)
server.register("john doe", "password2", False)
server.register("jane doe", "password3", False)


def menu():
    print("=" * 100)
    print("1. Register")
    print("2. Get Token")
    print("3. Set Token")
    print("4. Get flag")
    print("5. Exit")
    return int(input("choose option: "))


print("Welcome to the server!")
while True:
    choice = menu()
    if choice == 1:
        username = input("Username: ")
        password = input("Password: ")
        token = server.register(username, password)
        if token:
            print(f"Your token: {token}")
    elif choice == 2:
        username = input("Username: ")
        password = input("Password: ")
        token = server.get_token(username, password)
        if token:
            print(f"Your token: {token}")
    elif choice == 3:
        token = input("Token: ")
        server.set_token(token)
    elif choice == 4:
        server.get_flag()
    elif choice == 5:
        print("Bye!")
        break
