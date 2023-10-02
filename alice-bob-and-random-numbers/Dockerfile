FROM python:3.11-alpine
RUN apk add socat

COPY src/requirements.txt /requirements.txt
RUN pip install -r /requirements.txt

USER nobody
WORKDIR /home/nobody
COPY src .

EXPOSE 9999
CMD socat TCP-LISTEN:9999,reuseaddr,fork EXEC:"python3 -u chall.py"