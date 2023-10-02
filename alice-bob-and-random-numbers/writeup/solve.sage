# https://kel.bz/post/hnp/

from pwn import *
import random
from secrets import randbelow

#conn = process(['python3', 'chall.py'])
conn = remote('localhost', '2023')

N = 512
k = 100
d = 2 * ceil(sqrt(N))

res = conn.recvuntil(b'\n').strip()[len('Your lucky numbers: ')+1:-1].split(b', ')
lucky = list(map(lambda x:int(x.decode()), res))
g, p, c, ga, gb = lucky

inputs = []
answers = []
for _ in range(d):
    print(_)
    c = randbelow(p)
    conn.sendlineafter(b'> ', b'6')
    payload = str(ga * pow(g, c, p) % p).encode()
    conn.sendlineafter(b'your public secret: ', payload)
    inputs.append(pow(gb, c, p))

    conn.sendlineafter(b'> ', b'2')
    msb = 0
    for i in range(k):
        res = conn.recvuntil(b'\n').strip()
        msb |= int(res.decode())
        if i == k - 1:
            conn.sendlineafter(b'more? (y/n): ', b'n')
        else:
            conn.sendlineafter(b'more? (y/n): ', b'y')
    answers.append(msb << (N // 2))

def build_basis(oracle_inputs):
    """Returns a basis using the HNP game parameters and inputs to our oracle
    """
    basis_vectors = []
    for i in range(d):
        p_vector = [0] * (d+1)
        p_vector[i] = p
        basis_vectors.append(p_vector)
    basis_vectors.append(list(oracle_inputs) + [QQ(1)/QQ(p)])
    return Matrix(QQ, basis_vectors)

def approximate_closest_vector(basis, v):
    """Returns an approximate CVP solution using Babai's nearest plane algorithm.
    """
    BL = basis.LLL()
    G, _ = BL.gram_schmidt()
    _, n = BL.dimensions()
    small = vector(ZZ, v)
    for i in reversed(range(n)):
        c = QQ(small * G[i]) / QQ(G[i] * G[i])
        c = c.round()
        small -= BL[i] * c
    return (v - small).coefficients()

lattice = build_basis(inputs)
u = vector(ZZ, answers + [0])
v = approximate_closest_vector(lattice, u)

ab = (v[-1] * p) % p
conn.sendlineafter(b'> ', b'7')
conn.sendlineafter(b'secret: ', str(ab).encode())
print(conn.recvuntil(b'\n').strip())