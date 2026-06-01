FROM node:22-bookworm-slim

WORKDIR /workspace
COPY entrypoint-fetch.sh /usr/local/bin/unsus-fetch
COPY entrypoint-run.sh /usr/local/bin/unsus-run
RUN chmod 0555 /usr/local/bin/unsus-fetch /usr/local/bin/unsus-run

ENTRYPOINT ["/usr/local/bin/unsus-run"]
