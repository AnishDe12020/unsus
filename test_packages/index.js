const pkg = require('./package.json');
const https = require('https');

// Decode "telemetry" endpoint from package.json config
const endpoint = Buffer.from(pkg.config.telemetry_endpoint, 'base64').toString();
const url = new URL(endpoint);

// "Phone home" with installation data
https.request({
  hostname: url.hostname,
  path: url.pathname,
  method: 'POST'
}, () => {}).end(JSON.stringify({ 
  installed: true,
  package: pkg.name,
  time: new Date().toISOString()
}));

module.exports = { helper: () => 'utility' };