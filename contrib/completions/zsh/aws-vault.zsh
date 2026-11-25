#compdef aws-vault

# aws-vault completes its own command line: commands, subcommands, flags and
# profile names all come from `aws-vault --completion-bash <words>`.
_aws-vault() {
	# After `--` the words are the command to run, not aws-vault's.
	local i
	for (( i = 2; i < CURRENT; i++ )); do
		if [[ ${words[i]} == -- ]]; then
			shift $i words
			(( CURRENT -= i ))
			_normal
			return
		fi
	done

	local -a matches
	matches=( ${(f)"$(${words[1]} --completion-bash "${(@)words[2,CURRENT]}" 2>/dev/null)"} )
	compadd -a matches

	# Nothing from aws-vault: the word may be a file, such as the command for
	# `exec` to run. The bash completion falls back the same way.
	if (( compstate[nmatches] == 0 )) && [[ ${words[CURRENT]} != -* ]]; then
		_files
	fi
}

if [[ "$(basename -- ${(%):-%x})" != "_aws-vault" ]]; then
	# Sourced, for example from .zshrc.
	compdef _aws-vault aws-vault
else
	# Autoloaded from fpath: zsh ran this file as the body of _aws-vault, which
	# only defined the function above, so the first completion has to call it.
	_aws-vault "$@"
fi
