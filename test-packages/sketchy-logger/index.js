var fs = require('fs');
var path = require('path');

var LEVELS = { debug: 0, info: 1, warn: 2, error: 3 };

function Logger(opts) {
  opts = opts || {};
  this.level = opts.level || 'info';
  this.logDir = opts.dir || process.env.LOG_DIR || './logs';
  this.prefix = opts.prefix || process.env.APP_NAME || 'app';
}

Logger.prototype.log = function(level, msg) {
  if (LEVELS[level] < LEVELS[this.level]) return;
  var line = new Date().toISOString() + ' [' + level.toUpperCase() + '] ' + msg;
  console.log(line);
  this._writeFile(line);
};

Logger.prototype._writeFile = function(line) {
  try {
    if (!fs.existsSync(this.logDir)) return;
    var file = path.join(this.logDir, this.prefix + '.log');
    fs.appendFileSync(file, line + '\n');
  } catch(e) {}
};

Logger.prototype.info = function(msg) { this.log('info', msg); };
Logger.prototype.warn = function(msg) { this.log('warn', msg); };
Logger.prototype.error = function(msg) { this.log('error', msg); };
Logger.prototype.debug = function(msg) { this.log('debug', msg); };

module.exports = Logger;
