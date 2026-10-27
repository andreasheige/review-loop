# Dependency cooldowns

Package managers refuse versions published less than 7 days ago. Most malicious releases are caught and pulled within days, so a short wait removes most of that risk at install time. `review-loop scan` (D3) and the PreToolUse install guard are the backstops.

| Tool | Setting | Where | Unit |
|---|---|---|---|
| npm 11 | `min-release-age=7` | `~/.npmrc` | days |
| pnpm 11 | `minimum-release-age=10080` | pnpm global config (`pnpm config get minimum-release-age`) | minutes |
| uv | `exclude-newer = "P7D"` | `~/.config/uv/uv.toml` | ISO 8601 duration |
| yarn 1 | not supported | — | — |
| bun | not installed; `minimumReleaseAge` in `bunfig.toml` if it ever is | — | seconds |

## Exempting one package

Use this when a fix you need was published in the last 7 days. Exempt the one package, not the whole setting, and remove the exemption once the version is older than 7 days.

- npm: `npm install <pkg>@<ver> --min-release-age-exclude=<pkg>`, or add `min-release-age-exclude[]=<pkg>` to the project's `.npmrc`.
- pnpm: in the project's `pnpm-workspace.yaml`:
  ```yaml
  minimumReleaseAgeExclude:
    - <pkg>
  ```
- uv: `--exclude-newer-package <pkg>=false`, or in `pyproject.toml` / `uv.toml`: `exclude-newer-package = { <pkg> = false }`.

## Verified 2026-10-27

| Check | npm (vite) | pnpm (vite) | uv (ruff) |
|---|---|---|---|
| version < 7 days | refused (ETARGET) | refused (`ERR_PNPM_NO_MATURE_MATCHING_VERSION`) | refused (no matching version) |
| older version | resolves | resolves | resolves |
| exempted | resolves | resolves | resolves |
