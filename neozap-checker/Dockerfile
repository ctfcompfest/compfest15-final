FROM ubuntu:22.04

RUN useradd -m ctf

RUN apt-get update && \
    apt-get install -y libssl-dev

WORKDIR /home/ctf
USER ctf

COPY src/server /home/ctf/server
COPY src/server.c /home/ctf/server.c
COPY src/login.html /home/ctf/login.html
COPY src/secret.html /home/ctf/secret.html

RUN chmod -R 750 /home/ctf && \
    chmod 555 /home/ctf/*.html /home/ctf/*.c
RUN chmod +x /home/ctf/server

CMD ["/home/ctf/server"]
