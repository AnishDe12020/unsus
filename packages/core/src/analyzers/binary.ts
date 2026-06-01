import path from "node:path";

import type { ExtractedPackage, Finding, PackageFile } from "../types.js";
import { createFinding } from "./finding.js";

const EXECUTABLE_EXTENSIONS = new Set([".exe", ".dll", ".so", ".dylib", ".node", ".sh", ".ps1", ".bat", ".cmd"]);

export function analyzeBinary(pkg: ExtractedPackage): Finding[] {
  const findings: Finding[] = [];

  for (const file of pkg.files) {
    const extension = path.extname(file.path).toLowerCase();
    if (EXECUTABLE_EXTENSIONS.has(extension)) {
      findings.push(
        createFinding({
          category: "binary_payload",
          type: "executable_extension",
          severity: [".sh", ".ps1", ".bat", ".cmd"].includes(extension) ? "warning" : "danger",
          title: "Executable file extension",
          message: `Package contains executable-looking file ${file.path}.`,
          file: file.path,
          evidence: { extension },
          confidence: 0.85
        })
      );
    }

    const headerType = binaryHeaderType(file);
    if (headerType) {
      findings.push(
        createFinding({
          category: "binary_payload",
          type: "binary_header",
          severity: "danger",
          title: `${headerType} binary header`,
          message: `Package file ${file.path} has a ${headerType} binary header.`,
          file: file.path,
          evidence: { headerType },
          confidence: 0.95
        })
      );
    }
  }

  return findings;
}

function binaryHeaderType(file: PackageFile): "ELF" | "PE" | "Mach-O" | undefined {
  const header = file.headerBytes;
  if (!header || header.length < 4) {
    return undefined;
  }

  if (header[0] === 0x7f && header[1] === 0x45 && header[2] === 0x4c && header[3] === 0x46) {
    return "ELF";
  }

  if (header[0] === 0x4d && header[1] === 0x5a) {
    return "PE";
  }

  const magic = Buffer.from(header.subarray(0, 4)).toString("hex");
  if (["feedface", "feedfacf", "cefaedfe", "cffaedfe", "cafebabe"].includes(magic)) {
    return "Mach-O";
  }

  return undefined;
}
