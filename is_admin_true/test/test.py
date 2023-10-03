from fulgens import Verdict, ChallengeHelper
from pwn import remote
from Crypto.Util.number import isPrime
from multiprocessing import TimeoutError
from multiprocessing.pool import ThreadPool
from pathlib import Path

    
def test(helper: ChallengeHelper):
    try:
        host, port = helper.addresses[0].split(":")
        io = remote(host, int(port))
        
        # check if parameters correctly set
        io.recvuntil(b'p = ')
        p = int(io.recvline().strip().decode())
        assert isPrime(p) or p.bit_length() == 256, "p is not prime or not 256 bits"
        io.recvuntil(b'g = ')
        g = int(io.recvline().strip().decode())
        io.recvuntil(b'm = ')
        m = int(io.recvline().strip().decode())
        assert m >> 16 < p, "m is too large"
        io.recvuntil(b'a = ')
        a = int(io.recvline().strip().decode())
        io.recvuntil(b'c = ')
        c = int(io.recvline().strip().decode())

        # check if register and set works
        username, password = 'swusjask', 'password'
        io.sendlineafter(b'choose option: ', b'1')
        io.sendlineafter(b'Username: ', username.encode())
        io.sendlineafter(b'Password: ', password.encode())
        io.recvuntil(b'Your token: ')
        token = io.recvline().strip().decode()
        io.sendlineafter(b'choose option: ', b'3')
        io.sendlineafter(b'Token: ', token.encode())
        io.recvuntil(b'Welcome, ')
        assert username == io.recvline().strip().decode(), "username not match"

        # check if get token and set token works
        io.sendlineafter(b'choose option: ', b'2')
        io.sendlineafter(b'Username: ', username.encode())
        io.sendlineafter(b'Password: ', password.encode())
        io.recvuntil(b'Your token: ')
        token = io.recvline().strip().decode()
        io.sendlineafter(b'choose option: ', b'3')
        io.sendlineafter(b'Token: ', token.encode())
        io.recvuntil(b'Welcome, ')
        assert username == io.recvline().strip().decode(), "username not match"

        # check if get flag works
        username, password = 'admin', helper.secret
        io.sendlineafter(b'choose option: ', b'2')
        io.sendlineafter(b'Username: ', username.encode())
        io.sendlineafter(b'Password: ', password.encode())
        io.recvuntil(b'Your token: ')
        token = io.recvline().strip().decode()
        io.sendlineafter(b'choose option: ', b'3')
        io.sendlineafter(b'Token: ', token.encode())
        io.sendlineafter(b'choose option: ', b'4')
        flag = io.recvline().decode()
        assert 'flag{' in flag, "flag not found"
        
        # exit
        io.sendlineafter(b'choose option: ', b'5')
        io.close()

        return Verdict.OK()
    
    except AssertionError as e:
        return Verdict.FAIL(str(e))

def do_check(helper: ChallengeHelper) -> Verdict:
    testcase_func = [test]
    pool = ThreadPool(processes=len(testcase_func))

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
        addresses=["127.0.0.1:2024"],
        secret='REPLACEME',
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
