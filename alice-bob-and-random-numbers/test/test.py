from fulgens import Verdict, ChallengeHelper
from multiprocessing import TimeoutError
from multiprocessing.pool import ThreadPool
from pathlib import Path
from secrets import randbelow
import socket
import random

class Socket:
    def __init__(self, s):
        self.s = s

    def recvuntil(self, target):
        res = self.s.recv(1)
        while target not in res:
            res += bytes(self.s.recv(1))
        return res

    def sendlineafter(self, target, to_send):
        self.recvuntil(target)
        self.sendline(to_send)
    
    def sendline(self, to_send):
        self.s.send(to_send + b'\n')

    def send(self, to_send):
        self.s.send(to_send)
    
    def close(self):
        self.s.close()
    
def test0(helper: ChallengeHelper):
    try:
        host, port = helper.addresses[0].split(":")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, int(port)))
        s = Socket(s)

        # check if parameters are being outputted
        res = s.recvuntil(b'\n')
        res = res.strip()[len('Your lucky numbers: ')+1:-1].split(b', ')
        lucky = list(map(lambda x:int(x.decode()), res))
        g, p, c, ga, gb = lucky

        # exit
        s.sendlineafter(b'> ', b'8')

        s.close()
        return Verdict.OK()
    except Exception as e:
        print(e)
        return Verdict.FAIL("test 0 failed: " + str(e))

def test1(helper: ChallengeHelper):
    try:
        host, port = helper.addresses[0].split(":")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, int(port)))
        s = Socket(s)

        # check if parameters are being outputted
        res = s.recvuntil(b'\n')
        res = res.strip()[len('Your lucky numbers: ')+1:-1].split(b', ')
        lucky = list(map(lambda x:int(x.decode()), res))
        g, p, c, ga, gb = lucky

        # check if randomization is good enough
        k = 100
        for i in range(1, 4):
            s.sendlineafter(b'> ', str(i).encode())
            random_numbers = set()
            for _ in range(k):
                res = s.recvuntil(b'\n')
                random_numbers.add(int(res.strip().decode()))
                s.recvuntil(b'more? (y/n): ')
                if _ == k - 1:
                    s.sendline(b'n')
                else:
                    s.sendline(b'y')
            assert len(random_numbers) > 7 * k // 10
        
        # exit
        s.sendlineafter(b'> ', b'8')

        s.close()
        return Verdict.OK()
    except Exception as e:
        return Verdict.FAIL("test 1 failed: " + str(e))

def test2(helper: ChallengeHelper):
    try:
        host, port = helper.addresses[0].split(":")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, int(port)))
        s = Socket(s)

        # check if parameters are being outputted
        res = s.recvuntil(b'\n')
        res = res.strip()[len('Your lucky numbers: ')+1:-1].split(b', ')
        lucky = list(map(lambda x:int(x.decode()), res))
        g, p, c, ga, gb = lucky
        
        # check flag exists
        s.sendlineafter(b'> ', b'4')
        s.sendlineafter(b'password: ', helper.secret.encode())
        a = int(s.recvuntil(b'\n').strip().decode())
        assert pow(g, a, p) == ga

        s.sendlineafter(b'> ', b'5')
        s.sendlineafter(b'password: ', helper.secret.encode())
        b = int(s.recvuntil(b'\n').strip().decode())
        assert pow(g, b, p) == gb

        s.sendlineafter(b'> ', b'7')
        s.sendlineafter(b'secret: ', str(pow(g, a * b, p)).encode())
        flag = s.recvuntil(b'\n').strip().decode()
        assert 'flag{' in flag # flag format

        # check this menu is available
        s.sendlineafter(b'> ', b'6')
        s.sendlineafter(b'your public secret: ', str(randbelow(p)).encode())

        # exit
        s.sendlineafter(b'> ', b'8')

        s.close()
        return Verdict.OK()
    except Exception as e:
        return Verdict.FAIL("test 2 failed: " + str(e))

def do_check(helper: ChallengeHelper) -> Verdict:
    testcase_func = [test0, test1, test2]
    pool = ThreadPool(processes=10)

    tc_res = [pool.apply_async(func, args=(helper, )) for func in testcase_func]

    pool.close()
    pool.join()

    for res in tc_res:
        verdict = res.get()
        if not verdict.is_ok():
            return verdict
    return Verdict.OK()

if __name__ == "__main__":
    helper = ChallengeHelper(
        addresses=["127.0.0.1:2023"],
        secret='__TEAM_SECRET__',
        local_challenge_dir=Path(__file__).parent.parent,
        compose_filename="docker-compose.dev.yml",
    )

    # AnD Checker will call do_check() in the following way
    INTERVAL_SECOND = 30
    TIMEOUT_SECOND = INTERVAL_SECOND // 3
    
    main_pool = ThreadPool(processes=1)
    check_process = main_pool.apply_async(do_check, args=(helper, ))
    main_pool.close()
    
    try:
        verdict = check_process.get(TIMEOUT_SECOND)
    except TimeoutError:
        main_pool.terminate()
        verdict = Verdict.FAIL("timeout.")
    
    print("Result:", verdict.status, verdict.message)