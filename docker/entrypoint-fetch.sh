#!/bin/sh
# Container 1: HAS network, downloads deps only
# No scripts run — just fetch source files

cp -r /pkg/* /workspace/ 2>/dev/null || true
cd /workspace

# install deps with scripts disabled — safe, just downloads
npm install --ignore-scripts 2>&1 | tee /output/fetch.log
EXIT=$?

cat > /output/fetch-meta.json <<EOF
{"exitCode":$EXIT}
EOF

exit 0
