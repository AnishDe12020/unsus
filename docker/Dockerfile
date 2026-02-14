FROM node:20-alpine

RUN apk add --no-cache procps coreutils

COPY entrypoint.sh /entrypoint.sh
COPY monitor-resources.sh /monitor-resources.sh
COPY net-hook.js /net-hook.js
RUN chmod +x /entrypoint.sh /monitor-resources.sh

WORKDIR /workspace
ENTRYPOINT ["/entrypoint.sh"]
