FROM node:20-bookworm-slim

RUN apt update && \
    apt install -y --no-install-recommends ca-certificates bzip2 fontconfig libfontconfig && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/app
COPY editor/package.json .
RUN npm i --production
RUN npm install -g phantomjs-prebuilt --unsafe-perm

COPY editor .
RUN npm run build

COPY startup.sh .
RUN chmod +x startup.sh

ENTRYPOINT "./startup.sh"