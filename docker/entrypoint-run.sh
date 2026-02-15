#!/bin/sh
# Container 2: NO network, runs lifecycle scripts
# net-hook.js captures all outbound connection attempts via NODE_OPTIONS
# Deps already installed by container 1

cd /workspace

# preload net-hook to capture hostnames before DNS resolution
export NODE_OPTIONS="--require=/net-hook.js"

# start resource monitor
/monitor-resources.sh &
MON_PID=$!

# snapshot before scripts
find /workspace -type f 2>/dev/null | sort > /output/fs-before.txt || true

START=$(date +%s%3N)
EXIT=0
> /output/install.log

if [ -f package.json ]; then
  for HOOK in preinstall install postinstall; do
    SCRIPT=$(node --require /dev/null -e "try{const p=require('./package.json');p.scripts&&p.scripts['$HOOK']&&console.log(p.scripts['$HOOK'])}catch{}" 2>/dev/null)
    if [ -n "$SCRIPT" ]; then
      echo "[unsus] running $HOOK: $SCRIPT" >> /output/install.log
      timeout 15s sh -c "$SCRIPT" >> /output/install.log 2>&1 || EXIT=$?
    fi
  done
fi
END=$(date +%s%3N)

# snapshot after scripts
find /workspace -type f 2>/dev/null | sort > /output/fs-after.txt || true

# diff fs
comm -13 /output/fs-before.txt /output/fs-after.txt > /output/fs-changes.log 2>/dev/null || true

# filter out npm registry from network.log (legitimate traffic from npm install)
if [ -f /output/network.log ]; then
  grep -v 'registry.npmjs.org' /output/network.log > /output/network-filtered.log 2>/dev/null || true
  mv /output/network-filtered.log /output/network.log
fi

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
