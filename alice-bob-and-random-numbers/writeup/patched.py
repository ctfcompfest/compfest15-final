from Crypto.Util.number import getPrime, bytes_to_long
from secrets import randbelow
import os
import random
import signal
import sys

class Unbuffered(object):
    def __init__(self, stream):
        self.stream = stream
    def write(self, data):
        self.stream.write(data)
        self.stream.flush()
    def writelines(self, datas):
        self.stream.writelines(datas)
        self.stream.flush()
    def __getattr__(self, attr):
        return getattr(self.stream, attr)

sys.stdout = Unbuffered(sys.stdout)

n = 512
g = 2
p = getPrime(n)
password = os.getenv('PASSWORD')

class Secret():
    def __init__(self, account1, account2):
        self.secret = pow(account2.public_secret, account1.secret, p)

class Account():
    def __init__(self, public_secret=None):
        if public_secret != None:
            self.public_secret = public_secret
        else:
            self.secret = randbelow(p)
            self.public_secret = pow(g, self.secret, p)

def menu():
    print('===== Menu =====')
    print('1. Talk to Alice')
    print('2. Talk to Bob')
    print('3. Talk to Alice and Bob')
    print('4. I am Alice')
    print('5. I am Bob')
    print('6. Set lucky numbers')
    print('7. Flag, I want flag!')
    print('8. Exit')
    choice = int(input('> '))
    return choice

def get_random(secret):
    return bytes_to_long(os.urandom(16))

def talk(secret):
    while True:
        print(get_random(secret.secret))
        more = input('more? (y/n): ').strip()
        if more == 'n':
            break

def i_am(account):
    password_input = input('password: ').strip()
    if password == password_input:
        print(account.secret)

def get_flag(secret):
    secret_input = input('secret: ').strip()
    if secret.secret == int(secret_input):
        print(os.popen('cat /flag/flag.txt').read())

def main():
    signal.alarm(60)
    alice = Account()
    bob = Account()
    you = Account()

    alice_and_bob = Secret(alice, bob)
    alice_and_you = Secret(alice, you)
    bob_and_you = Secret(bob, you)

    print(f'Your lucky numbers: {(g, p, you.secret, alice.public_secret, bob.public_secret)}')

    while True:
        try:
            choice = menu()
            if choice == 1:
                talk(alice_and_you)
            if choice == 2:
                talk(bob_and_you)
            if choice == 3:
                talk(alice_and_bob)
            if choice == 4:
                i_am(alice)
            if choice == 5:
                i_am(bob)
            if choice == 6:
                public_secret = int(input('your public secret: ').strip())
                you = Account(public_secret)
                alice_and_you = Secret(alice, you)
                bob_and_you = Secret(bob, you)
            if choice == 7:
                get_flag(alice_and_bob)
            if choice == 8:
                break
        except:
            print('something error happened.')
            break
    print('bye.')

if __name__ == '__main__':
    main()
