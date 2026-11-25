#!/usr/bin/env zsh
# Presses TAB in a real interactive zsh and prints what its completion system
# did with a command line.
#
#   complete.zsh source <completion-script> '<command line up to the cursor>'
#   complete.zsh fpath  <dir holding _aws-vault> '<command line up to the cursor>'
#
# Prints the candidates zsh listed and the command line after the TAB:
#
#   list: demo plain
#   buffer: [aws-vault exec ]
#
# zsh has no way to ask "what would you complete here?", so this drives one
# through a pty. It never waits a fixed time: zsh reads keys in order, so the
# key bound to the `finish` widget is only handled once the TAB before it has
# completed, however long that took, and its DONE marker ends the read.

emulate -L zsh
zmodload zsh/zpty || exit 2

local mode=$1 target=$2 line=$3
local timeout=${ZSH_COMPLETION_TEST_TIMEOUT:-60}

local setup
case $mode in
	source) setup="autoload -U compinit && compinit -u -d /dev/null; source ${(q)target}" ;;
	fpath)  setup="fpath=(${(q)target} \$fpath); autoload -U compinit && compinit -u -d /dev/null" ;;
	*)      print -u2 "usage: $0 source|fpath <target> <line>"; exit 2 ;;
esac

# read_until <marker>: appends pty output to $buf until it holds marker.
local buf
read_until() {
	local chunk deadline=$(( SECONDS + timeout ))
	buf=
	while [[ $buf != *$1* ]]; do
		if (( SECONDS > deadline )); then
			print -u2 "timed out after ${timeout}s waiting for $1; zsh printed:"
			print -u2 -r -- "$buf"
			zpty -d z
			exit 3
		fi
		zpty -r -t z chunk && buf+=$chunk || sleep 0.05
	done
}

zpty -b z zsh -f -i
zpty -w z "PS1='P> ' PROMPT_EOL_MARK=; unsetopt zle_bracketed_paste; LISTMAX=10000; $setup"
# The markers are spelled in two halves so that the pty echoing these commands
# back does not look like the markers themselves.
zpty -w z 'finish() { print; print -r -- "BUFFER:[$BUFFER]"; print DO""NE; BUFFER= }; zle -N finish; bindkey "^E" finish; print REA""DY'
read_until READY

zpty -w -n z "$line"$'\t'$'\x05'
read_until DONE
zpty -d z

# Drop terminal control sequences, then everything that is not a candidate:
# the prompt and the echoes of the command line.
local clean=$(print -r -- "$buf" | sed -e $'s/\x1b\\[[0-9;?]*[a-zA-Z]//g' -e $'s/[\x0f\x07\x08]//g' | tr '\r' '\n')
local -a candidates
candidates=( ${(f)"$(print -r -- "$clean" | sed -n '/^BUFFER:/q;p' | grep -v -e "${line%% *}" -e '^P> ' | tr -s ' \t' '\n' | grep -v -e '^$' -e '^P>$' | sort -u)"} )

print -r -- "list: ${candidates[*]}"
print -r -- "buffer: $(print -r -- "$clean" | sed -n 's/^BUFFER://p' | tail -1)"
