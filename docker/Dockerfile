FROM node:20-alpine

RUN apk add --no-cache procps coreutils strace

COPY entrypoint.sh /entrypoint.sh
COPY monitor-resources.sh /monitor-resources.sh
COPY parse-strace.sh /parse-strace.sh
RUN chmod +x /entrypoint.sh /monitor-resources.sh /parse-strace.sh

WORKDIR /workspace
ENTRYPOINT ["/entrypoint.sh"]
