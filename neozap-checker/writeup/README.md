# Writeup NeoZap Checker

### Vulnerability
1. Hashed password bof that's able to overwrite return value.
2. Bad regex check. It allows arbitrary number of whitespace, and is done on `buffer` instead of `request`.
3. No null-terminator on buffer.

### Solution
1. Bruteforce to find password with regex pattern `[a-f0-9]{88}dafa[a-f0-9]{4}`, so we can utilize vuln #1 to get authenticated.
2. Because of vuln #2 and #3, we can forge fake requests using multiple requests partially. For example, if we want to call `GET /../flag/flag.txt`, we could call `GET  /./xlag/xlag.txt`, followed by `GET  /./xlag/f`, `GET  /./f`, `GET /.`, which will construct to `GET /../flag/flag.txt`.

### Patching
1. Fix the HASH_LENGTH to 48
2. Either add null-terminator on buffer, or fix the regex to not allow arbitrary whitespace and/or to not accept `/` on the `route` part.