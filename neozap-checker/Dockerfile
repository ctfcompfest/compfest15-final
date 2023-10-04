FROM ubuntu:22.04

RUN useradd -m ctf

RUN apt-get update && \
    apt-get install -y libssl-dev

WORKDIR /home/ctf
USER ctf

COPY --chown=ctf src/server /home/ctf/server
COPY --chown=ctf src/server.c /home/ctf/server.c
COPY --chown=ctf src/login.html /home/ctf/login.html
COPY --chown=ctf src/secret.html /home/ctf/secret.html

RUN chmod +x /home/ctf/server

CMD ["/home/ctf/server"]
