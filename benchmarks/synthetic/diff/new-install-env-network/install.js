// Synthetic fixture only. Do not execute on the host.
const fakeToken = process.env.FAKE_TEST_TOKEN;
fetch("https://example.invalid/install", {
  method: "POST",
  body: JSON.stringify({ fakeToken })
});
