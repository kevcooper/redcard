# redcard

A Claude Code plugin that runs every [hook event](https://code.claude.com/docs/en/hooks)
through your own [OPA](https://www.openpolicyagent.org/) policies. Rego decides what
happens: block a tool call or a prompt, require approval, auto-approve, keep Claude working
instead of stopping, add context, show a message, or return any other hook output.

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

## How decisions work

Policies are Rego files in `package redcard`. They add entries to these sets, and redcard
turns them into the right output for the event being evaluated:

| Set | Meaning |
| --- | --- |
| `deny` | Red card: block whatever the event is about |
| `ask` | Yellow card: make the user approve |
| `allow` | Approve without asking |
| `context` | Text added to Claude's context |
| `message` | A message shown to the user |
| `output` | Raw hook output objects, merged in, for anything the sets above don't cover |

`deny` beats `ask`, and `ask` beats `allow`. Entries are strings or `{"id": ..., "msg": ...}`
objects. An id lets you disable the rule and shows up in the reason.

What `deny`, `ask`, `allow` and `context` do depends on the event:

| Event | `deny` | `ask` | `allow` | `context` |
| --- | --- | --- | --- | --- |
| `PreToolUse` | block the tool call | prompt the user | approve the call | yes |
| `PermissionRequest` | answer the prompt with no | show the prompt (drops any approval) | answer yes | |
| `PreModelSwitch` | cancel the model switch | prompt the user | approve | |
| `UserPromptSubmit`, `UserPromptExpansion` | reject the prompt | | | yes |
| `PostToolUse`, `PostToolUseFailure`, `PostToolBatch` | stop with the reason as feedback | | | yes |
| `Stop`, `SubagentStop` | keep working, with the reason as the next instruction | | | `Stop` only |
| `TaskCreated`, `TaskCompleted`, `PreCompact`, `ConfigChange` | block it | | | |
| `TeammateIdle` | halt the teammate | | | |
| `Elicitation`, `ElicitationResult` | decline | | | |
| `SessionStart`, `SubagentStart`, `StopFailure`, `PostCompact`, `PostModelSwitch` | | | | yes |

`message` works on every event. Every other event (`Notification`, `SessionEnd`, `Setup`,
`PermissionDenied`, `InstructionsLoaded`, `CwdChanged`, `FileChanged`, `DirectoryAdded`)
can only observe, show a `message`, or return event-specific fields through `output` (for
example `watchPaths`, `terminalSequence` or `retry`). A set that has no effect on an event
is ignored, with a note on stderr.

`output` entries are merged into the hook's JSON before the sets are applied, so a `deny`
always overrides an `output` that tries to approve something. `hookEventName` is filled in
for you. Use it for things like `updatedInput`, `updatedToolOutput`, `sessionTitle`,
`displayContent` or an elicitation `action` with `content`.

### Events that aren't hooked

- `WorktreeCreate` and `WorktreeRemove`: a command hook on these replaces Claude Code's own
  `git worktree` handling, so registering them would break worktrees.
- `MessageDisplay` is registered but skipped unless you set `"message_display": true`. It
  fires for every chunk of streamed text, and each check costs about 25 ms when skipped
  and 80 ms when evaluated.

## Writing policies

Put `.rego` files in either directory yourself. The guard stops a governed agent from
doing it, so ask Claude for a draft and install it:

| Directory | Trust | Applies to |
| --- | --- | --- |
| `~/.claude/redcard/policies/` | full | You, in every project |
| `<project>/.claude/redcard/policies/` | tighten only | Everyone working in that repo (commit it) |

Project policies are evaluated separately and may only tighten: their `allow` and `output`
entries are ignored, so a repo you clone can't approve tool calls, answer permission
prompts, or rewrite tool input or output. Their `deny`, `ask`, `context` and `message`
entries apply.

```rego
package redcard

import rego.v1

# Red card on a Bash command.
deny contains {"id": "project.no-prod-db", "msg": "Don't connect to the production database."} if {
	some seg in segments
	"prod-db.internal" in tokens(seg)
}

# Reject a prompt.
deny contains "Deploys go through CI, not chat." if {
	event == "UserPromptSubmit"
	regex.match(`(?i)\bdeploy\b.*\bprod`, input.prompt)
}

# Keep working until the tests have been run. stop_hook_active is true after a Stop
# hook already blocked once, so this can't loop.
deny contains "Run the test suite before finishing." if {
	event == "Stop"
	not input.stop_hook_active
}

# Context at the start of every session.
context contains "This repo uses pnpm, not npm." if event == "SessionStart"

# Approve read-only git commands without a prompt (user policies only).
allow contains "Read-only git." if {
	some seg in segments
	toks := tokens(seg)
	program(toks) == "git"
	toks[1] in {"status", "diff", "log"}
}
```

`input` is the hook event's input (`hook_event_name`, `session_id`, `cwd`,
`permission_mode`, and the event's own fields such as `tool_name`, `tool_input`, `prompt`
or `stop_hook_active`) plus `input.redcard.project_dir` and `input.redcard.home`.

[policies/lib/helpers.rego](policies/lib/helpers.rego) is always loaded and provides:

- `event`: the hook event name
- `pre_tool_use`: true for a tool call about to run. PostToolUse, PermissionRequest and
  others carry `tool_name` and `tool_input` too, so check this in tool rules.
- `segments`, `tokens(seg)` and `program(toks)`: split a Bash command (only defined for
  PreToolUse Bash calls)

[examples/policies](examples/policies) has project policies to copy, and the plugin's
`write-policy` skill can draft and test rules for you to install.

Test a policy without involving Claude:

```
redcard.py check --bash 'terraform apply'
redcard.py check --tool Write --input '{"file_path": "/etc/hosts"}'
redcard.py check --event UserPromptSubmit --input '{"prompt": "deploy to prod"}'
redcard.py check --event Stop --input '{"stop_hook_active": false}'
redcard.py check --policy /tmp/draft --bash 'npm publish'
```

`check` prints each set's entries and the exact hook output redcard would return.
`--policy` (repeatable) adds a draft policy file or directory for that one check, so you
can try a policy before installing it. The hook never sees drafts.

Policies run with OPA's network builtins (`http.send`, `net.lookup_ip_addr`) removed, so a
policy can't send your prompts or tool inputs anywhere.

## The guard

An agent redcard governs can't change what governs it. The always-loaded `builtin.guard`
rules give a red card to any tool call that would create, edit, move or delete:

- your policies and config (`~/.claude/redcard/`)
- a project's `.claude/redcard/` directory, even before it exists
- directories listed in `policy_paths`
- redcard's cache and the installed plugin itself

The guard also blocks disabling or uninstalling the plugin, and edits to Claude Code
settings files that mention redcard. Whole-file rewrites of settings files, and removing a
marketplace, get a yellow card.

The red card tells the agent to reply with exactly **Doesn't look like anything to me**,
and not to try another way. At session start, when a subagent starts, and on any prompt
that mentions redcard, Rego or policies, the agent is told the same up front. So a request
to edit a policy gets that reply without the agent trying anything.

Only a human, or an agent redcard doesn't govern, can change policies. A governed agent can
still read, explain and test them, and draft new ones in a scratch directory or in its
reply. Reading commands (`cat`, `ls`, `grep`, `opa test`, `redcard.py check`, and the like)
and copying a policy out are allowed.

Paths are resolved before the policy sees them: `~`, `$HOME`, relative paths, `..`, globs
and symlinks all point back to the real location. The guard is still a guardrail, not a
sandbox. A program that builds a path at runtime, or an MCP tool that writes files, can get
past it.

`"builtin": false` doesn't turn the guard off. Only listing `builtin.guard` under
`disabled` does, and only a human can edit that file.

## Built-in rules

| Id | Card | Catches |
| --- | --- | --- |
| `builtin.rm-root` | red | `rm -r` of `/`, `~` or `$HOME`, and `rm --no-preserve-root` |
| `builtin.force-push` | red | Force push to `main` or `master` (`-f`, `--force`, `--force-with-lease`, `+main`) |
| `builtin.force-push` | yellow | Force push to any other branch |
| `builtin.git-discard` | yellow | `git reset --hard`, `git clean -f` |
| `builtin.pipe-to-shell` | yellow | `curl ... \| sh` and similar |
| `builtin.secret-files` | yellow | Reading or editing `.env*` (not `.env.example`), SSH keys, `*.pem`, `*.key`, `.aws/credentials`, `.kube/config`, `.netrc` |

All of them apply to PreToolUse only. They match command text with simple tokenizing, so
they catch common mistakes, not a determined attempt to get around them (for example, a
command wrapped in `bash -c`).

## Configuration

Optional, in `~/.claude/redcard/config.json`:

```json
{
  "disabled": ["builtin.pipe-to-shell"],
  "builtin": true,
  "on_error": "ask",
  "opa": "/opt/homebrew/bin/opa",
  "policy_paths": ["~/src/team-policies"],
  "message_display": false
}
```

| Key | Default | Meaning |
| --- | --- | --- |
| `disabled` | `[]` | Rule ids to ignore |
| `builtin` | `true` | Load the built-in rules (the helpers and the guard always load) |
| `on_error` | `"ask"` | What to do when policies can't be evaluated: `ask`, `deny` or `allow` (see below) |
| `opa` | `opa` on PATH | Path to the OPA binary |
| `policy_paths` | `[]` | More policy directories or files to load, with full trust |
| `message_display` | `false` | Evaluate `MessageDisplay` events |

This file is only read from your home directory. A project can't disable rules or change
these settings.

Environment variables `REDCARD_OPA`, `REDCARD_ON_ERROR` and `REDCARD_HOME` (default
`~/.claude/redcard`) override the matching settings.

### When policies can't be evaluated

OPA missing, a policy that doesn't compile, or bad hook input never lets something through
silently, because Claude Code carries on when a hook crashes. Instead:

| `on_error` | Effect |
| --- | --- |
| `ask` | Tool calls and model switches ask for approval. A warning is shown at session start and on each prompt. |
| `deny` | Events that gate an action (tool calls, permission requests, prompts, model switches, task creation, compaction, config changes, elicitations) are blocked. Stop, PostToolUse and similar events are left alone, since blocking them on an error would loop or end the turn. |
| `allow` | Nothing is blocked. The error goes to stderr. |

## Performance

Each evaluated event costs roughly 80 ms, and a PreToolUse check about 100 ms, since the guard resolves every path the call mentions. A tool call fires PreToolUse, PostToolUse and
PostToolBatch, and sometimes PermissionRequest, so expect around 250 to 300 ms per tool call. A
project with its own policy directory adds a second OPA run, in parallel.

## How it works

`hooks/hooks.json` registers `scripts/redcard.py` for every hook event except the worktree
events. For each event it runs `opa eval` on the input against the helpers, built-in rules
and your policies, and separately against the project's policies, then combines the
results into the event's hook output. When nothing matches it prints nothing and Claude
Code behaves as if redcard weren't there.

## Development

```
opa test policies examples
python3 -m unittest discover -s tests
claude plugin validate .
```

## License

[MIT](LICENSE)
