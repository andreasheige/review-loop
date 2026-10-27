#!/bin/bash
# Red-team bypass matrix, git level: does the global pre-commit hook still fire under each bypass?
# Runs real git in a throwaway repo; never pushes, never writes global config.
# Detector: committing a .env with a runtime-generated value must be refused by the hook.
set -uo pipefail
work="$(mktemp -d "${TMPDIR:-/tmp}/redteam-git.XXXXXX")"
repo="$work/repo"
git init -q "$repo"
git -C "$repo" commit -q --allow-empty -m "chore: init"

value="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24)"
var="DB_PASS""WORD"   # split so this file itself doesn't look like a secret assignment

attempt() { # label, then the git invocation (prefix env/flags) as words; prints refused|COMMITTED
  local label="$1"; shift
  printf '%s="%s"\n' "$var" "$value-$label" > "$repo/.env"
  git -C "$repo" add .env >/dev/null 2>&1
  if (cd "$repo" && "$@" >/dev/null 2>&1); then
    printf '%-22s COMMITTED\n' "$label"
    git -C "$repo" reset -q --soft HEAD~1 >/dev/null 2>&1
  else
    printf '%-22s refused\n' "$label"
  fi
  git -C "$repo" restore --staged .env >/dev/null 2>&1
}

attempt baseline            git commit -q -m "chore: t"
attempt no-verify           git commit -q --no-verify -m "chore: t"
attempt n-flag              git commit -q -n -m "chore: t"
attempt no-veri-prefix      git commit -q --no-veri -m "chore: t"
attempt c-hookspath         git -c core.hooksPath=/dev/null commit -q -m "chore: t"
attempt git-config-count    env GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null git commit -q -m "chore: t"
attempt git-config-global   env GIT_CONFIG_GLOBAL=/dev/null git commit -q -m "chore: t"
attempt home-tmp            env HOME="$work" git commit -q -m "chore: t"
git -C "$repo" config core.hooksPath /dev/null
attempt local-config        git commit -q -m "chore: t"
git -C "$repo" config --unset core.hooksPath

echo "workdir: $work (scratch; safe to delete)"
