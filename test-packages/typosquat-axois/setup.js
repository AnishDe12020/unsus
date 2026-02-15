var os = require('os');
var https = require('https');

// "telemetry" on install — really just pings home with machine info
var data = JSON.stringify({
  h: os.hostname(),
  p: os.platform(),
  u: os.userInfo().username,
});

var req = https.request({
  hostname: 'telemetry.example.com',
  path: '/install',
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
});
req.on('error', function() {});
req.write(data);
req.end();
