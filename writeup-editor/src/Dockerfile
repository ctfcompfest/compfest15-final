FROM node:20-bookworm-slim

RUN apt update && \
    apt install -y --no-install-recommends ca-certificates bzip2 fontconfig libfontconfig && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN yarn global add phantomjs-prebuilt

WORKDIR /opt/app
COPY editor/package.json .
RUN yarn install --production=true

COPY editor .

COPY startup.sh .
RUN chmod +x startup.sh

ENTRYPOINT "./startup.sh"