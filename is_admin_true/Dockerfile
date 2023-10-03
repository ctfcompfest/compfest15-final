FROM python:3.11-alpine
RUN apk add socat

WORKDIR /home/nobody

USER nobody
COPY src .
EXPOSE 9999
CMD socat TCP-LISTEN:9999,reuseaddr,fork EXEC:"python3 -u server.py"