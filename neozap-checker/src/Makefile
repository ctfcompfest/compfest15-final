all:
	gcc -fno-stack-protector -Wl,-z,relro,-z,now -o server server.c -lssl -lcrypto