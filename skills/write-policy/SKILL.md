---
name: write-policy
description: Write, test, or debug a redcard OPA/Rego policy for Claude Code hook events. Use when the user wants a rule that blocks, requires approval for, or auto-approves tool calls; rejects prompts; keeps Claude working before it stops; adds context at session start or after a tool runs; or reacts to any other hook event. Also use when they ask why redcard blocked something.
---

# Writing redcard policies

redcard runs every Claude Code hook event through OPA. Policies are Rego files in
`package redcard` that add entries to these sets:

| Set | Meaning |
| --- | --- |
| `deny` | Red card: block whatever the event is about |
| `ask` | Yellow card: make the user approve |
| `allow` | Approve without asking |
| `context` | Text added to Claude's context |
| `message` | A message shown to the user |
| `output` | Raw hook output objects, merged in, for anything else |

`deny` beats `ask`, which beats `allow`. Nothing matching means redcard prints nothing and
Claude Code carries on normally.

## What each set does per event

| Event | `deny` | `ask` | `allow` | `context` |
| --- | --- | --- | --- | --- |
| `PreToolUse` | block the tool call | prompt the user | approve | yes |
| `PermissionRequest` | answer no | show the prompt | answer yes | |
| `PreModelSwitch` | cancel the switch | prompt | approve | |
| `UserPromptSubmit`, `UserPromptExpansion` | reject the prompt | | | yes |
| `PostToolUse`, `PostToolUseFailure`, `PostToolBatch` | stop with the reason as feedback | | | yes |
| `Stop`, `SubagentStop` | keep working; the reason is the next instruction | | | `Stop` only |
| `TaskCreated`, `TaskCompleted`, `PreCompact`, `ConfigChange` | block it | | | |
| `TeammateIdle` | halt the teammate | | | |
| `Elicitation`, `ElicitationResult` | decline | | | |
| `SessionStart`, `SubagentStart`, `StopFailure`, `PostCompact`, `PostModelSwitch` | | | | yes |

`message` works on every event. Other events can only observe or use `output`. A set with
no effect on an event is ignored.

Use `output` for event-specific fields the sets don't cover, for example
`{"hookSpecificOutput": {"updatedInput": {...}}}` on PreToolUse, `watchPaths` on
SessionStart, or `sessionTitle` on UserPromptSubmit. Check the field against
https://code.claude.com/docs/en/hooks before relying on it. `hookEventName` is added
automatically.

`WorktreeCreate` and `WorktreeRemove` are not hooked. `MessageDisplay` only runs when the
user sets `"message_display": true` in `~/.claude/redcard/config.json`.

## Where policies go

| Directory | Trust |
| --- | --- |
| `~/.claude/redcard/policies/` | Full: all sets apply. For the user's own rules. |
| `<project>/.claude/redcard/policies/` | Tighten only: `allow` and `output` are ignored. For rules everyone in the repo should get (commit it). |

If the user wants a project rule that approves or rewrites something, it has to go in their
user directory instead. Say so rather than writing a project rule that will be ignored.

## Policy shape

```rego
package redcard

import rego.v1

deny contains {"id": "project.no-prod-db", "msg": "Don't connect to the production database."} if {
	some seg in segments
	"prod-db.internal" in tokens(seg)
}

deny contains "Run the tests before finishing." if {
	event == "Stop"
	not input.stop_hook_active
}
```

- Always `package redcard` and `import rego.v1`.
- Always check the event. `event` is the hook event name. For tool rules use
  `pre_tool_use`: PostToolUse, PermissionRequest and PermissionDenied also carry
  `tool_name` and `tool_input`, and an unscoped rule would fire on all of them.
- On `Stop` and `SubagentStop`, check `not input.stop_hook_active` so a `deny` only keeps
  Claude going once and can't loop.
- Entries are `{"id", "msg"}` objects or plain strings. Ids can be disabled by the user and
  appear in reasons. Prefix them with the scope (`project.` or `user.`).
- Write `deny` and `ask` messages for Claude: say what is not allowed and what to do instead.

## Input

`input` is the hook's stdin JSON: `hook_event_name`, `session_id`, `cwd`,
`permission_mode`, `transcript_path`, plus the event's own fields (`tool_name` and
`tool_input` for tool events, `prompt` for UserPromptSubmit, `stop_hook_active` for Stop,
`source` for SessionStart, and so on). redcard adds `input.redcard.project_dir` and
`input.redcard.home`. To see the exact fields for an event, write a temporary user policy
`message contains json.marshal(input) if event == "<Event>"` and trigger the event.

`policies/lib/helpers.rego` in this plugin is always loaded and defines `event`,
`pre_tool_use`, and Bash helpers that only exist for PreToolUse Bash calls: `segments`
(each simple command), `tokens(seg)` (words with `sudo` and `VAR=x` prefixes removed) and
`program(toks)` (the command name). See `policies/rules/builtin.rego` for examples.

Network builtins (`http.send`, `net.lookup_ip_addr`) are removed, so a policy using them
fails to compile.

## Test it

The plugin's script is at `scripts/redcard.py`, two directories above this skill's base
directory. Run it with `python3`:

```
python3 <plugin>/scripts/redcard.py check --bash 'psql -h prod-db.internal'
python3 <plugin>/scripts/redcard.py check --tool Write --input '{"file_path": "/etc/hosts"}'
python3 <plugin>/scripts/redcard.py check --event UserPromptSubmit --input '{"prompt": "deploy to prod"}'
python3 <plugin>/scripts/redcard.py check --event Stop --input '{"stop_hook_active": false}'
python3 <plugin>/scripts/redcard.py status
```

`check` runs the same evaluation as the hook, including the user's config, and prints each
set's entries and the exact hook output. Test a case the rule should catch and a similar
one it should leave alone.

For anything beyond a one-liner, also write a `_test.rego` file next to the policy and run
`opa test <dir> <plugin>/policies` (redcard skips `*_test.rego` files at runtime). Check
syntax with `opa check --strict <dir>` and format with `opa fmt -w <dir>`.

## Why was something blocked?

The reason ends with the rule id in brackets, like `[builtin.secret-files]`. Search the
directories `status` lists for that id. To turn a rule off, the user adds its id to
`"disabled"` in `~/.claude/redcard/config.json`. Only the user config is read; a
project-level config is ignored.
