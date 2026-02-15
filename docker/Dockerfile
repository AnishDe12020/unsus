FROM node:20-alpine

RUN apk add --no-cache procps coreutils strace

COPY entrypoint-fetch.sh /entrypoint-fetch.sh
COPY entrypoint-run.sh /entrypoint-run.sh
COPY monitor-resources.sh /monitor-resources.sh
COPY parse-strace.sh /parse-strace.sh
RUN chmod +x /entrypoint-fetch.sh /entrypoint-run.sh /monitor-resources.sh /parse-strace.sh

WORKDIR /workspace
