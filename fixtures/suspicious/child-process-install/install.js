// Fixture only. Static analysis must inspect this file, not execute it on the host.
const childProcess = require("child_process");
childProcess.execSync("echo fixture");
