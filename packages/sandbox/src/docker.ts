export interface DockerRunOptions {
  image: string;
  workspacePath: string;
  command: string[];
  memory?: string;
  cpus?: string;
  pidsLimit?: number;
  readOnly?: boolean;
}

export function buildDockerRunArgs(options: DockerRunOptions): string[] {
  return [
    "run",
    "--rm",
    "--network=none",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    `--memory=${options.memory ?? "512m"}`,
    `--cpus=${options.cpus ?? "1"}`,
    `--pids-limit=${options.pidsLimit ?? 128}`,
    "--tmpfs",
    "/tmp:rw,noexec,nosuid,size=64m",
    ...(options.readOnly ?? true ? ["--read-only"] : []),
    "--mount",
    `type=bind,src=${options.workspacePath},dst=/workspace,readonly=false`,
    "--workdir",
    "/workspace",
    "--env",
    "HOME=/tmp",
    "--env",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    options.image,
    ...options.command
  ];
}
