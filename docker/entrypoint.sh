#!/bin/sh

# start resource monitor
/monitor-resources.sh &
MON_PID=$!

# copy package source
cp -r /pkg/* /workspace/ 2>/dev/null || true
cd /workspace

# PHASE 1: install dependencies (needs network, scripts disabled — safe)
npm install --ignore-scripts 2>&1 | tee /output/install-deps.log || true

# rebuild native addons (safe, not straced)
npm rebuild 2>/dev/null || true

# snapshot AFTER dep install + rebuild
find /workspace -type f 2>/dev/null | sort > /output/fs-before.txt || true

# PHASE 2: run lifecycle scripts under strace
# Only these are suspicious — they run arbitrary code from the package author
# Signal resource monitor to start recording now (not during npm install/rebuild)
touch /output/.phase2
START=$(date +%s%3N)
EXIT=0
> /output/strace.log

if [ -f package.json ]; then
  for HOOK in preinstall install postinstall; do
    SCRIPT=$(node -e "try{const p=require('./package.json');p.scripts&&p.scripts['$HOOK']&&console.log(p.scripts['$HOOK'])}catch{}" 2>/dev/null)
    if [ -n "$SCRIPT" ]; then
      timeout 15s strace -f -e trace=connect -o /output/strace-${HOOK}.log \
        sh -c "$SCRIPT" 2>&1 | tee -a /output/install.log || EXIT=$?
      cat /output/strace-${HOOK}.log >> /output/strace.log 2>/dev/null || true
    fi
  done
fi
END=$(date +%s%3N)

# parse strace output into network.log
/parse-strace.sh /output/strace.log

# snapshot after scripts
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
