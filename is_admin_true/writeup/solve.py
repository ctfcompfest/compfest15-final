from sage.all import *
from pwn import process, context, remote

def get_params():
    io.recvuntil(b"p = ")
    p = int(io.recvline().decode().strip())
    io.recvuntil(b"g = ")
    g = int(io.recvline().decode().strip())
    io.recvuntil(b"m = ")
    m = int(io.recvline().decode().strip())
    io.recvuntil(b"a = ")
    a = int(io.recvline().decode().strip())
    io.recvuntil(b"c = ")
    c = int(io.recvline().decode().strip())
    return p, g, m, a, c

def register(username, password):
    io.sendlineafter(b"choose option: ", b"1")
    io.sendlineafter(b"Username: ", username.encode())
    io.sendlineafter(b"Password: ", password.encode())
    io.recvuntil(b"Your token: ")
    return int(io.recvline().decode().strip(), 16)

def get_token(username, password):
    io.sendlineafter(b"choose option: ", b"2")
    io.sendlineafter(b"Username: ", username.encode())
    io.sendlineafter(b"Password: ", password.encode())
    io.recvuntil(b"Your token: ")
    return int(io.recvline().decode().strip(), 16)

def get_flag(token):
    io.sendlineafter(b"choose option: ", b"3")
    io.sendlineafter(b"Token: ", token.encode())
    io.sendlineafter(b"choose option: ", b"4")
    return io.recvline().decode().strip()
    
# io = process(['python3', './server.py'])
io = remote('localhost', 2024)
p, g, m, a, c = get_params()
Fp = GF(p)
g = Fp(g)
x = []
first_token = Fp(register("swusjask", "password"))
token = first_token
for _ in range(2):
    next_token = Fp(get_token("swusjask", "password"))
    s = int((next_token / token).log(g))
    x.append(s)
    token = next_token

for i in range(1 << 16):
    state1 = x[0] << 16 | i
    state2 = (a * state1 + c) % m
    if state2 >> 16 == x[1]:
        state = state1
        break

token = first_token
for _ in range(3):
    state = (state - c) * pow(a, -1, m) % m
    token = g ** -(state >> 16) * token

print(get_flag(hex(int(token))))