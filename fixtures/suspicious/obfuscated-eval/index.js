// Fixture only. Static analysis must inspect this file, not execute it on the host.
const payload = "ZnVuY3Rpb24gZmFrZSgpIHsgcmV0dXJuICdmaXh0dXJlJzsgfQ==";
eval(Buffer.from(payload, "base64").toString("utf8"));
