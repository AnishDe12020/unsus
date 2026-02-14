#!/bin/sh
echo "ts,cpu,mem" > /output/resources.csv
while true; do
  TS=$(date +%s%3N)
  ps aux | awk -v t=$TS 'NR>1{c+=$3;m+=$6}END{printf "%s,%.1f,%.1f\n",t,c,m/1024}' >> /output/resources.csv
  sleep 0.2
done
