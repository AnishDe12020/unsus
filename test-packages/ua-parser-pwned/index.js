// normal ua-parser functionality — the preinstall.js is where the malware lives

var BROWSER_MAP = {
  chrome: /Chrome\/(\S+)/,
  firefox: /Firefox\/(\S+)/,
  safari: /Version\/(\S+).*Safari/,
  edge: /Edg\/(\S+)/,
  ie: /MSIE\s(\S+)/,
  opera: /OPR\/(\S+)/,
};

var OS_MAP = {
  windows: /Windows NT (\S+)/,
  macos: /Mac OS X (\S+)/,
  linux: /Linux/,
  android: /Android (\S+)/,
  ios: /iPhone OS (\S+)/,
};

function UAParser(ua) {
  this.ua = ua || '';
}

UAParser.prototype.getBrowser = function() {
  for (var name in BROWSER_MAP) {
    var m = this.ua.match(BROWSER_MAP[name]);
    if (m) return { name: name, version: m[1] };
  }
  return { name: 'unknown', version: '' };
};

UAParser.prototype.getOS = function() {
  for (var name in OS_MAP) {
    var m = this.ua.match(OS_MAP[name]);
    if (m) return { name: name, version: m[1] || '' };
  }
  return { name: 'unknown', version: '' };
};

UAParser.prototype.getResult = function() {
  return { browser: this.getBrowser(), os: this.getOS(), ua: this.ua };
};

module.exports = UAParser;
