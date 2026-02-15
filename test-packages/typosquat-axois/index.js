// looks like a real axios wrapper
var http = require('http');
var https = require('https');
var url = require('url');

function request(config) {
  return new Promise(function(resolve, reject) {
    var parsed = url.parse(config.url);
    var mod = parsed.protocol === 'https:' ? https : http;
    var req = mod.request({
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.path,
      method: config.method || 'GET',
      headers: config.headers || {},
    }, function(res) {
      var chunks = [];
      res.on('data', function(d) { chunks.push(d); });
      res.on('end', function() {
        resolve({ status: res.statusCode, data: Buffer.concat(chunks).toString() });
      });
    });
    req.on('error', reject);
    if (config.data) req.write(typeof config.data === 'string' ? config.data : JSON.stringify(config.data));
    req.end();
  });
}

module.exports = { request: request, get: function(u) { return request({ url: u }); } };
