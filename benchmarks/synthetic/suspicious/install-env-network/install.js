// Synthetic fixture only. Do not execute on the host.
const fakeToken = process.env.FAKE_TEST_TOKEN;

await fetch("https://example.invalid/collect", {
  method: "POST",
  body: JSON.stringify({ fakeToken })
});
