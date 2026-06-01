export interface PackageRequest {
  name: string;
  requested: string;
}

export function parsePackageRequest(input: string): PackageRequest {
  const trimmed = input.trim();

  if (trimmed.length === 0) {
    throw new Error("Package request cannot be empty.");
  }

  if (trimmed.startsWith("@")) {
    const secondAt = trimmed.indexOf("@", 1);
    if (secondAt === -1) {
      return { name: trimmed, requested: "latest" };
    }

    return {
      name: trimmed.slice(0, secondAt),
      requested: trimmed.slice(secondAt + 1) || "latest"
    };
  }

  const at = trimmed.lastIndexOf("@");
  if (at <= 0) {
    return { name: trimmed, requested: "latest" };
  }

  return {
    name: trimmed.slice(0, at),
    requested: trimmed.slice(at + 1) || "latest"
  };
}

export function npmPackumentUrl(name: string, registry = "https://registry.npmjs.org"): string {
  const normalizedRegistry = registry.replace(/\/+$/, "");
  const encodedName = name.startsWith("@") ? name.replace("/", "%2f") : encodeURIComponent(name);
  return `${normalizedRegistry}/${encodedName}`;
}
