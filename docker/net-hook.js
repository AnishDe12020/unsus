// preloaded via NODE_OPTIONS=--require — logs all outbound connection attempts
var fs = require('fs');
var origConnect = require('net').Socket.prototype.connect;

require('net').Socket.prototype.connect = function() {
  var args = arguments;
  var host = '';
  if (typeof args[0] === 'object' && args[0] !== null) {
    host = args[0].host || args[0].hostname || '';
  } else if (typeof args[1] === 'string') {
    host = args[1];
  }
  if (host && host !== '127.0.0.1' && host !== 'localhost') {
    try { fs.appendFileSync('/output/network.log', host + '\n'); } catch(e) {}
  }
  return origConnect.apply(this, args);
};
