#!/bin/sh
set -e

# start resource monitor
/monitor-resources.sh &
MON_PID=$!

# copy package source
cp -r /pkg/* /workspace/ 2>/dev/null || true
cd /workspace

# snapshot AFTER copy, so copied files don't show as "new"
find /workspace -type f 2>/dev/null | sort > /output/fs-before.txt || true

# run npm install under strace to capture ALL connect() syscalls (node, curl, binaries, etc)
START=$(date +%s%3N)
EXIT=0
timeout 25s strace -f -e trace=connect -o /output/strace.log \
  npm install --ignore-scripts=false 2>&1 | tee /output/install.log || EXIT=$?
END=$(date +%s%3N)

# parse strace output into network.log
/parse-strace.sh /output/strace.log

# snapshot after install
find /workspace -type f 2>/dev/null | sort > /output/fs-after.txt || true

# diff fs
comm -13 /output/fs-before.txt /output/fs-after.txt > /output/fs-changes.log 2>/dev/null || true

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
