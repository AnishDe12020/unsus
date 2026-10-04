# @unsus/sandbox

Opt-in lifecycle-script observation for unsus using Docker with networking disabled, resource limits and a copied workspace. Requires Node.js 22+ and running Docker with the `node:22-bookworm-slim` image available. Missing Docker or unavailable images fail the command; scripts never fall back to host execution.

This is an experimental observation aid, not a proven boundary for hostile code. It does not trace network attempts, analyze dependencies, or detect sandbox escapes. Use harmless synthetic fixtures for development. See the [repository documentation](https://github.com/AnishDe12020/unsus#readme).
