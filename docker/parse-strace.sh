#!/bin/sh
# Extract connect() targets from strace output, filtering out loopback and unix sockets
# Outputs unique "ip:port" lines to /output/network.log

grep 'connect(' "$1" \
  | grep 'sa_family=AF_INET' \
  | sed -n 's/.*sin6\?_port=htons(\([0-9]*\)).*inet6\?_addr("\([^"]*\)").*/\2:\1/p' \
  | grep -v '^127\.' \
  | grep -v '^::1:' \
  | grep -v '^0\.0\.0\.0:' \
  | sort -u > /output/network.log
