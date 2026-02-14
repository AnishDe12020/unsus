#!/bin/sh
set -e

export NODE_OPTIONS="--require=/net-hook.js"

# start resource monitor
/monitor-resources.sh &
MON_PID=$!

# init network log (hook appends to it)
touch /output/network.log

# copy package source
cp -r /pkg/* /workspace/ 2>/dev/null || true
cd /workspace

# snapshot AFTER copy, so copied files don't show as "new"
find /workspace -type f 2>/dev/null | sort > /output/fs-before.txt || true

# run npm install with timeout
START=$(date +%s%3N)
EXIT=0
timeout 25s npm install --ignore-scripts=false 2>&1 | tee /output/install.log || EXIT=$?
END=$(date +%s%3N)

# snapshot after install
find /workspace -type f 2>/dev/null | sort > /output/fs-after.txt || true

# diff fs
comm -13 /output/fs-before.txt /output/fs-after.txt > /output/fs-changes.log 2>/dev/null || true

# dedup network log
sort -u /output/network.log -o /output/network.log 2>/dev/null || true

# write meta
DURATION=$(( (END - START) / 1000 ))
TIMED_OUT="false"
if [ "$EXIT" = "124" ] || [ "$EXIT" = "137" ]; then
  TIMED_OUT="true"
fi

cat > /output/meta.json <<METAEOF
{"exitCode":$EXIT,"duration":$DURATION,"timedOut":$TIMED_OUT}
METAEOF

# kill monitor
kill $MON_PID 2>/dev/null || true
sleep 0.3

exit 0
