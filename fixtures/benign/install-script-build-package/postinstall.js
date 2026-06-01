// Harmless fixture. Dynamic tests must run this only inside the sandbox.
import { writeFileSync } from "node:fs";

writeFileSync("build-marker.txt", "fixture build completed\n");
