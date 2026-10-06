---
name: write-policy
description: Write, test, or debug a redcard OPA/Rego policy that blocks (deny) or requires approval for (ask) Claude Code tool calls. Use when the user wants to add a rule, guardrail, or restriction on what Claude may run, read, or edit, or asks why redcard blocked something.
---

# Writing redcard policies

redcard runs every tool call through OPA before it executes. Policies are Rego files in
`package redcard` that add entries to two sets:

- `deny`: red card. The call is blocked and Claude sees the message.
- `ask`: yellow card. The user must approve the call, even in modes that auto-approve.

If any `deny` entry matches, the call is blocked. Otherwise, if any `ask` entry matches, the
user is prompted. Otherwise redcard does nothing and normal permissions apply. Policies
cannot allow anything, only tighten.

## Where policies go

| Scope | Directory |
| --- | --- |
| Just this user, every project | `~/.claude/redcard/policies/` |
| Everyone working in this repo (commit it) | `<project>/.claude/redcard/policies/` |

Pick the project directory when the rule is about this codebase, the user directory when
it's a personal preference. Ask if it's unclear.

## Policy shape

```rego
package redcard

import rego.v1

deny contains {"id": "project.no-prod-db", "msg": "Don't connect to the production database."} if {
	input.tool_name == "Bash"
	contains(input.tool_input.command, "prod-db.internal")
}
```

- Always `package redcard` and `import rego.v1`.
- Entries are objects with `id` and `msg`. Use an id prefix for the scope (`project.` or
  `user.`) so it can't collide with `builtin.` rules. A plain string also works but can't be
  disabled by id.
- Write `msg` for Claude: say what is not allowed and what to do instead.

## Input

`input` is the PreToolUse hook event plus a `redcard` object:

| Field | Example |
| --- | --- |
| `input.tool_name` | `Bash`, `Read`, `Edit`, `Write`, `WebFetch`, `mcp__github__create_pull_request` |
| `input.tool_input` | `{"command": "..."}` for Bash, `{"file_path": "..."}` for Read/Edit/Write |
| `input.cwd`, `input.permission_mode`, `input.session_id` | from Claude Code |
| `input.redcard.project_dir` | the project root |
| `input.redcard.home` | the user's home directory |

`policies/lib/helpers.rego` in this plugin defines helpers you can use in any policy, since
it shares the package and is always loaded: `segments` (each simple command in a Bash string),
`tokens(seg)` (a segment's words, with `sudo` and `VAR=x` prefixes removed), and
`program(toks)` (the command name). See `policies/rules/builtin.rego` for examples before writing Bash rules.

Network builtins (`http.send`, `net.lookup_ip_addr`) are removed, so policies can't send
tool inputs anywhere. A policy that uses them fails to compile.

## Test it

The plugin's script is at `scripts/redcard.py`, two directories above this skill's base
directory. Run it with `python3`:

```
python3 <plugin>/scripts/redcard.py check --bash 'psql -h prod-db.internal'
python3 <plugin>/scripts/redcard.py check --tool Write --input '{"file_path": "/etc/hosts"}'
python3 <plugin>/scripts/redcard.py status
```

`check` prints RED CARD, YELLOW CARD or "play on" with the reasons, and runs the same
evaluation the hook does, including the user's config. `status` lists the OPA binary and
policy directories in effect.

For anything beyond a one-liner, also write a `_test.rego` file next to the policy and run
`opa test <dir> <plugin>/policies` (redcard skips `*_test.rego` files at runtime). Test both a
call the rule should catch and a similar one it should leave alone.

Check syntax with `opa check --strict <dir>` and format with `opa fmt -w <dir>`.

## Why was something blocked?

The reason ends with the rule id in brackets, like `[builtin.secret-files]`. To find the
rule, search the policy directories from `status` for that id. To turn a rule off, the user
adds its id to `"disabled"` in `~/.claude/redcard/config.json`. Only the user config can
disable rules; don't add a project-level config for it, because redcard ignores one.
