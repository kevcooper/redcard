# redcard

A Claude Code plugin that runs every tool call through your own
[OPA](https://www.openpolicyagent.org/) policies before it executes.

- **Red card** (`deny`): the call is blocked, and Claude is told why.
- **Yellow card** (`ask`): you have to approve the call, even in modes that would otherwise
  auto-approve it.
- **Play on**: no policy matched, so Claude Code's normal permissions apply.

Policies can only tighten what Claude may do. They can't approve anything on their own.

## Requirements

- macOS or Linux
- Python 3.9+ as `python3` (standard library only)
- [OPA](https://www.openpolicyagent.org/docs#1-download-opa) 0.59 or later on your PATH

## Install

redcard is listed in the [kevcooper plugin marketplace](https://github.com/kevcooper/claude-plugins):

```
/plugin marketplace add kevcooper/claude-plugins
/plugin install redcard@kevcooper
```

Then start a new session. Check the setup from your terminal:

```
python3 ~/.claude/plugins/cache/kevcooper/redcard/*/scripts/redcard.py status
```

## Built-in rules

| Id | Card | Catches |
| --- | --- | --- |
| `builtin.rm-root` | red | `rm -r` of `/`, `~` or `$HOME`, and `rm --no-preserve-root` |
| `builtin.force-push` | red | Force push to `main` or `master` (`-f`, `--force`, `--force-with-lease`, `+main`) |
| `builtin.force-push` | yellow | Force push to any other branch |
| `builtin.git-discard` | yellow | `git reset --hard`, `git clean -f` |
| `builtin.pipe-to-shell` | yellow | `curl ... \| sh` and similar |
| `builtin.secret-files` | yellow | Reading or editing `.env*` (not `.env.example`), SSH keys, `*.pem`, `*.key`, `.aws/credentials`, `.kube/config`, `.netrc` |

These match command text with simple tokenizing. They catch common mistakes, not a
determined attempt to get around them (for example, a command wrapped in `bash -c`).

## Writing policies

Put `.rego` files in either directory:

| Directory | Applies to |
| --- | --- |
| `~/.claude/redcard/policies/` | You, in every project |
| `<project>/.claude/redcard/policies/` | Everyone working in that repo (commit it) |

A policy is `package redcard` and adds entries to `deny` or `ask`:

```rego
package redcard

import rego.v1

deny contains {"id": "project.no-prod-db", "msg": "Don't connect to the production database."} if {
	input.tool_name == "Bash"
	contains(input.tool_input.command, "prod-db.internal")
}
```

`input` is the [PreToolUse hook input](https://code.claude.com/docs/en/hooks)
(`tool_name`, `tool_input`, `cwd`, `permission_mode`, ...) plus `input.redcard.project_dir`
and `input.redcard.home`. Shared helpers for Bash commands (`segments`, `tokens`, `program`)
are in [policies/lib/helpers.rego](policies/lib/helpers.rego), and
[examples/policies](examples/policies) has project policies to copy: keep edits inside the
project, block manual deploys, and require approval for new dependencies and GitHub writes.

The plugin includes a `write-policy` skill, so you can also just ask Claude to write a rule.

Test a policy without involving Claude:

```
redcard.py check --bash 'terraform apply'
redcard.py check --tool Write --input '{"file_path": "/etc/hosts"}'
```

Policies run with OPA's network builtins (`http.send`, `net.lookup_ip_addr`) removed, so a
policy can't send your tool inputs anywhere.

## Configuration

Optional, in `~/.claude/redcard/config.json`:

```json
{
  "disabled": ["builtin.pipe-to-shell"],
  "builtin": true,
  "on_error": "ask",
  "opa": "/opt/homebrew/bin/opa",
  "policy_paths": ["~/src/team-policies"]
}
```

| Key | Default | Meaning |
| --- | --- | --- |
| `disabled` | `[]` | Rule ids to ignore |
| `builtin` | `true` | Load the built-in rules (the helpers always load) |
| `on_error` | `"ask"` | What to do when policies can't be evaluated (OPA missing, a policy doesn't compile): `ask`, `deny` or `allow` |
| `opa` | `opa` on PATH | Path to the OPA binary |
| `policy_paths` | `[]` | More policy directories or files to load |

This file is only read from your home directory. A project can add policies but can't
disable rules or change `on_error`, so a repo you clone can't turn redcard off.

Environment variables `REDCARD_OPA`, `REDCARD_ON_ERROR` and `REDCARD_HOME` (default
`~/.claude/redcard`) override the matching settings.

## How it works

`hooks/hooks.json` registers `scripts/redcard.py` as a PreToolUse hook for every tool. For
each call it runs `opa eval` on the hook input against the helpers, built-in rules, your
policies and the project's policies, and returns a `deny` or `ask` permission decision when
any rule matches. Each call adds roughly 50 to 100 ms.

Claude Code lets a tool call through if a hook crashes, so redcard turns every failure into
the `on_error` decision instead.

## Development

```
opa test policies examples
python3 -m unittest discover -s tests
claude plugin validate .
```

## License

[MIT](LICENSE)
