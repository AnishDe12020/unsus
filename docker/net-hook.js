// Preloaded via NODE_OPTIONS=--require
// Captures all outbound network attempts including hostnames
// Works with --network=none (logs before DNS resolution fails)

var fs = require('fs');

var seen = {};
function log(host, port) {
  if (!host || host === '127.0.0.1' || host === 'localhost' || host === '::1' || host === '0.0.0.0') return;
  var key = host + ':' + (port || 0);
  if (seen[key]) return;
  seen[key] = true;
  try { fs.appendFileSync('/output/network.log', key + '\n'); } catch(e) {}
}

// Patch http/https request to capture hostname before DNS
['http', 'https'].forEach(function(mod) {
  var m = require(mod);
  var origRequest = m.request;
  var origGet = m.get;

  m.request = function(opts) {
    if (typeof opts === 'string') {
      try { var u = new URL(opts); log(u.hostname, u.port || (mod === 'https' ? 443 : 80)); } catch(e) {}
    } else if (opts && typeof opts === 'object') {
      log(opts.hostname || opts.host || '', opts.port || (mod === 'https' ? 443 : 80));
    }
    return origRequest.apply(this, arguments);
  };

  m.get = function(opts) {
    if (typeof opts === 'string') {
      try { var u = new URL(opts); log(u.hostname, u.port || (mod === 'https' ? 443 : 80)); } catch(e) {}
    } else if (opts && typeof opts === 'object') {
      log(opts.hostname || opts.host || '', opts.port || (mod === 'https' ? 443 : 80));
    }
    return origGet.apply(this, arguments);
  };
});

// Also patch net.Socket.connect for raw TCP
var net = require('net');
var origConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function() {
  var args = arguments;
  var host = '', port = 0;
  if (typeof args[0] === 'object' && args[0] !== null) {
    host = args[0].host || args[0].hostname || '';
    port = args[0].port || 0;
  } else if (typeof args[0] === 'number') {
    port = args[0];
    host = typeof args[1] === 'string' ? args[1] : '';
  }
  if (host) log(host, port);
  return origConnect.apply(this, args);
};
