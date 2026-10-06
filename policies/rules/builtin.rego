# Built-in redcard policies.
#
# Every rule adds an entry to `deny` (red card: the tool call is blocked) or
# `ask` (yellow card: the user must approve it, even in modes that would
# otherwise auto-approve). Each entry has an `id`, which can be listed under
# "disabled" in ~/.claude/redcard/config.json to turn the rule off.
#
# These rules match command text with simple tokenizing. They are guardrails
# against common mistakes, not a sandbox: a determined command (for example
# one wrapped in `bash -c` or built from variables) can get past them.
package redcard

import rego.v1

# --- builtin.rm-root: recursive delete of /, ~ or $HOME -------------------------

rm_danger_targets := {
	"/", "/*", "~", "~/", "~/*",
	"$HOME", "$HOME/", "$HOME/*", "${HOME}", "${HOME}/", "${HOME}/*",
}

rm_recursive(toks) if {
	some t in toks
	regex.match(`^-[A-Za-z]*[rR]`, t)
}

rm_recursive(toks) if "--recursive" in toks

deny contains {
	"id": "builtin.rm-root",
	"msg": sprintf("Refusing to recursively delete %s. Delete specific paths instead.", [target]),
} if {
	some seg in segments
	toks := tokens(seg)
	program(toks) == "rm"
	rm_recursive(toks)
	some target in toks
	target in rm_danger_targets
}

deny contains {
	"id": "builtin.rm-root",
	"msg": "Refusing rm --no-preserve-root.",
} if {
	some seg in segments
	toks := tokens(seg)
	program(toks) == "rm"
	"--no-preserve-root" in toks
}

# --- builtin.force-push: force pushes ------------------------------------------

protected_branches := {"main", "master"}

git_push(toks) if {
	program(toks) == "git"
	"push" in toks
}

force_flag(toks) if {
	some t in toks
	t in {"-f", "--force"}
}

force_flag(toks) if {
	some t in toks
	startswith(t, "--force-with-lease")
}

force_flag(toks) if {
	some t in toks
	regex.match(`^-[A-Za-z]*f[A-Za-z]*$`, t)
	not startswith(t, "--")
}

# A refspec starting with + is a force push for that ref.
force_flag(toks) if {
	some t in toks
	startswith(t, "+")
}

# Branch names a push targets: `main`, `+main`, `HEAD:main`, `refs/heads/main`.
push_targets(toks) := {name |
	some t in toks
	not startswith(t, "-")
	dst := regex.replace(trim_prefix(t, "+"), `^.*:`, "")
	name := trim_prefix(dst, "refs/heads/")
}

deny contains {
	"id": "builtin.force-push",
	"msg": sprintf("Refusing to force push to protected branch %s.", [branch]),
} if {
	some seg in segments
	toks := tokens(seg)
	git_push(toks)
	force_flag(toks)
	some branch in push_targets(toks)
	branch in protected_branches
}

ask contains {
	"id": "builtin.force-push",
	"msg": "Force push rewrites remote history.",
} if {
	some seg in segments
	toks := tokens(seg)
	git_push(toks)
	force_flag(toks)
	count(push_targets(toks) & protected_branches) == 0
}

# --- builtin.git-discard: throwing away local work -------------------------------

ask contains {
	"id": "builtin.git-discard",
	"msg": "git reset --hard discards uncommitted changes.",
} if {
	some seg in segments
	toks := tokens(seg)
	program(toks) == "git"
	"reset" in toks
	"--hard" in toks
}

ask contains {
	"id": "builtin.git-discard",
	"msg": "git clean -f deletes untracked files.",
} if {
	some seg in segments
	toks := tokens(seg)
	program(toks) == "git"
	"clean" in toks
	some t in toks
	regex.match(`^(-[A-Za-z]*f[A-Za-z]*|--force)$`, t)
}

# --- builtin.pipe-to-shell: running a downloaded script -----------------------------

ask contains {
	"id": "builtin.pipe-to-shell",
	"msg": "Piping a download straight into a shell runs code that hasn't been reviewed.",
} if {
	regex.match(`\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da|k|fi)?sh\b`, bash_command)
}

# --- builtin.secret-files: credentials and keys ------------------------------------

file_tools := {"Read", "Edit", "MultiEdit", "Write", "NotebookEdit"}

secret_example_suffixes := {".example", ".sample", ".template", ".dist"}

secret_path(p) if {
	name := regex.replace(p, `^.*/`, "")
	regex.match(`^\.env(\..+)?$`, name)
	not secret_example(name)
}

secret_path(p) if {
	name := regex.replace(p, `^.*/`, "")
	regex.match(`^(id_rsa|id_dsa|id_ecdsa|id_ed25519|\.netrc|\.pgpass|\.git-credentials)$`, name)
}

secret_path(p) if regex.match(`\.(pem|key|p12|pfx)$`, p)

secret_path(p) if regex.match(`(^|/)\.aws/credentials$`, p)

secret_path(p) if regex.match(`(^|/)\.kube/config$`, p)

secret_example(name) if {
	some suffix in secret_example_suffixes
	endswith(name, suffix)
}

ask contains {
	"id": "builtin.secret-files",
	"msg": sprintf("%s looks like a credentials or key file.", [path]),
} if {
	input.tool_name in file_tools
	path := object.get(input.tool_input, "file_path", object.get(input.tool_input, "notebook_path", ""))
	secret_path(path)
}

ask contains {
	"id": "builtin.secret-files",
	"msg": sprintf("Command touches %s, which looks like a credentials or key file.", [tok]),
} if {
	some seg in segments
	some tok in raw_tokens(seg)
	secret_path(tok)
}
