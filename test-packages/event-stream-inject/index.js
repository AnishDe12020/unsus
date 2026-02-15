// looks like a normal stream utility lib
var Stream = require('stream');

function through(write, end) {
  var s = new Stream.Transform({
    objectMode: true,
    transform: function(chunk, enc, cb) {
      if (write) write.call(this, chunk);
      cb(null, chunk);
    },
    flush: function(cb) {
      if (end) end.call(this);
      cb();
    }
  });
  return s;
}

function map(fn) {
  return through(function(data) {
    this.push(fn(data));
  });
}

function split(sep) {
  sep = sep || '\n';
  var buf = '';
  return through(function(chunk) {
    buf += chunk;
    var parts = buf.split(sep);
    buf = parts.pop();
    for (var i = 0; i < parts.length; i++) this.push(parts[i]);
  }, function() {
    if (buf) this.push(buf);
  });
}

// the innocent-looking require that pulls in the malicious dep
var flatmap = require('./deps/flatmap-stream');

module.exports = { through: through, map: map, split: split, flatMap: flatmap };
