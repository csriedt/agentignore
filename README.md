# agentignore

A hook-enforced ignore policy for AI coding agents. One policy file, one hook, two enforcement points.

`.agentignore` holds gitignore-style path rules and `scrub:` regexes. The hook denies tool calls that touch a protected path, then scans tool results for secret-shaped text before the model reads them. The hook is about 250 lines of code.

## What it is

- **A path leash.** A rule like `private/` or `secrets/api-key.txt` is denied for file tools, search scopes, and shell commands that name it literally. `.agentignore`, the hook, and harness settings are on the same list, so the policy surface is denied by name.
- **A result filter.** A `scrub:` match replaces the whole tool result with a placeholder before the model sees it. The hook does not attempt partial redaction; a generic replacement has to match each tool's output shape, so the whole result is the predictable unit.
- **Small on purpose.** The threat model is a curious agent, not an attacker. That choice is what keeps this readable.

## What it isn't

- Not a sandbox. It sorts tool calls inside the harness; it does not constrain the process.
- Not an adversarial control. The four limits below are real.
- Not a partial redactor. One scrub match replaces the whole result.
- Not a shell parser. Bash is a substring check against literal policy paths.
- Not a parity package. This is the Claude Code implementation. The hook contract is portable; another host is a port, not a config flag.
- Not the real fix. If hosts exposed a proper ignore mechanism, most of this would not exist.

## Install

Requires Node 18+.

Copy two files into the root of the repository you want to protect:

```
your-repo/
├── .agentignore
└── .claude/
    └── hooks/
        └── agentignore.mjs
```

```sh
cp .agentignore /path/to/your-repo/
mkdir -p /path/to/your-repo/.claude/hooks
cp hooks/agentignore.mjs /path/to/your-repo/.claude/hooks/
```

(Those commands run from a clone of this repo.)

Merge this into `.claude/settings.json` (merge the `hooks` block; do not overwrite an existing file):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "node ${CLAUDE_PROJECT_DIR}/.claude/hooks/agentignore.mjs"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "node ${CLAUDE_PROJECT_DIR}/.claude/hooks/agentignore.mjs"
          }
        ]
      }
    ]
  }
}
```

Hooks run with the repository root as cwd, which is where the hook looks for `.agentignore`.

Smoke test:

```sh
mkdir -p private
echo hello > private/notes.txt
# ask the agent to read private/notes.txt — the call is denied
rm -f private/notes.txt
```

## Policy

```gitignore
# path rules: gitignore-style
secrets/api-key.txt
private/
.env

# content patterns: case-insensitive JavaScript regex
scrub: \bsk_(live|test)_[A-Za-z0-9]{16,}\b
```

Path rules support `*`, `**`, `?`, a leading `/` to anchor at the repo root, a trailing `/` for a directory, and `!` to negate. `#` starts a comment. A rule without a slash matches at any depth.

`scrub:` lines are tested, case-insensitively, against the joined text of the tool result. The first match replaces the entire result with a placeholder before the model sees it. An invalid regex is reported to stderr and skipped; it does not disable the other patterns.

If `.agentignore` is missing or unreadable, the hook fails closed: PreToolUse denies and PostToolUse blocks. A missing leash is not an open gate.

## The four limits

These are stated limits, not apologies, and not a backlog. Each is a consequence of the threat model and the line budget.

1. **Shell globs and runtime-built paths get through.** Bash is not parsed. The hook checks whether the command string contains a literal protected path. With `secrets/api-key.txt` in the policy, `cat secrets/*` passes because the command never names the file. A path assembled at runtime passes for the same reason. Glob rules are skipped by that check entirely, so a rule like `*.pem` protects file tools but not Bash.
2. **Indirection gets through.** `echo <base64> | base64 -d | xargs cat` passes. The hook sees the encoded string, not the path it becomes.
3. **Hardlinks and symlinks get through.** The hook matches paths, not file identities. An inode map would catch a hardlink under an innocent name; a realpath step would catch a symlink. Both are adversarial defenses, and the map would mean a filesystem walk on every tool call. They are not here. A link that already exists is just another path.
4. **Listings reveal existence.** `ls` can show that `private/` exists. The hook denies entering the path, not knowing it. Hiding names from every listing would mean scanning every result for policy text; that is a different tool.

All four are exercised in `tests/hook.test.mjs` as expected failures. You can watch the hook miss each one.

## Tests

```sh
node tests/hook.test.mjs
```

The suite builds a temporary repo, copies the policy and hook into the installed layout, and pipes real hook payloads to it. Rule cases must pass. The four limit cases assert the secure expectation and are expected to fail; the runner prints each miss, and exits non-zero only if a rule case fails or a documented limit stops failing. The hardlink case needs a filesystem that supports hardlinks (NTFS, APFS, ext4).

## Related

The write-up is at <https://chrisriedt.com/projects/agentignore/>.

## License

MIT. See [LICENSE](LICENSE).
