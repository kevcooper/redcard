# Helpers shared by all redcard policies. Always loaded, even with
# "builtin": false, so user and project policies can rely on them.
package redcard

import rego.v1

# --- Bash command helpers ----------------------------------------------------

bash_command := input.tool_input.command if input.tool_name == "Bash"

# Each simple command in the Bash string, split on ; && || | and newlines.
segments contains trim_space(seg) if {
	some seg in regex.split(`;|&&|\|\||\||\n`, bash_command)
	trim_space(seg) != ""
}

# Tokens of a segment with quote characters removed, so "$HOME"/* reads as $HOME/*.
raw_tokens(seg) := [regex.replace(t, `["']`, "") | some t in regex.split(`\s+`, seg)]

# Leading tokens that don't change which program runs.
wrapper_token(t) if t in {"sudo", "command", "exec", "nohup", "time"}

wrapper_token(t) if regex.match(`^[A-Za-z_][A-Za-z0-9_]*=`, t)

# Tokens of a segment starting at the program name.
tokens(seg) := array.slice(toks, start, count(toks)) if {
	toks := raw_tokens(seg)
	start := min({i | some i, t in toks; not wrapper_token(t)})
}

program(toks) := regex.replace(toks[0], `^.*/`, "")
