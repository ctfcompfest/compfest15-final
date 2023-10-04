FROM alpine:3.14

RUN apk update && apk upgrade

RUN apk add python3 \
    libcap \
    curl \
    wget \ 
    py3-pandas \
    py3-flask 

WORKDIR /opt/ctf/app
COPY server/ .
COPY Dockerfile .

RUN apk add python3-dev py3-pip
RUN mkdir -p /flag
RUN chown root:root /flag && \
    chmod 0600 /flag

RUN chmod 744 /tmp

CMD ["python3", "app.py"]