#!/usr/bin/env zsh
# Checks the zsh completion script against an aws-vault binary, in a real
# interactive zsh, both sourced and installed on fpath.
#
#   run.zsh <aws-vault binary> [<completion-script>]
#
# What aws-vault offers for each command line is covered for every shell by
# cli/completion_test.go; this checks the zsh script on top of it.

emulate -L zsh
local here=${0:A:h}
local binary=${1:A} script=${2:-$here/../aws-vault.zsh}
script=${script:A}
[[ -x $binary ]] || { print -u2 "usage: $0 <aws-vault binary> [<completion-script>]"; exit 2 }

local tmp=$(mktemp -d)
trap 'rm -rf $tmp' EXIT
mkdir -p $tmp/bin $tmp/fpath $tmp/home
ln -s $binary $tmp/bin/aws-vault
cp $script $tmp/fpath/_aws-vault
cat > $tmp/config <<'CONFIG'
[sso-session my-sso]
sso_start_url=https://sso.example/start
sso_region=eu-west-1

[profile demo]
sso_session=my-sso

[profile plain]
region=eu-west-1
CONFIG
export PATH=$tmp/bin:$PATH HOME=$tmp/home AWS_CONFIG_FILE=$tmp/config

local failures=0 checks=0 mode target
# check <command line> <list|has|buffer> <expected>
#   list:   the listed candidates are exactly <expected>
#   has:    the listed candidates include every word of <expected>
#   buffer: the command line after TAB is <expected>
check() {
	local out got field=$2
	out=$(zsh -f $here/complete.zsh $mode $target "$1") || { print -r -- "FAIL  $mode  [$1]<TAB> harness error"; (( failures++ )); return }
	(( checks++ ))
	[[ $field == has ]] && field=list
	got=${${(M)${(f)out}:#$field:*}#$field: }
	local ok=0
	case $2 in
		has) ok=1; local w; for w in ${=3}; do [[ " $got " == *" $w "* ]] || ok=0; done ;;
		*)   [[ $got == $3 ]] && ok=1 ;;
	esac
	if (( ok )); then
		print -r -- "ok    $mode  [$1]<TAB> $2 = $3"
	else
		print -r -- "FAIL  $mode  [$1]<TAB> $2 = $got   (want $3)"
		(( failures++ ))
	fi
}

for mode target in source $script fpath $tmp/fpath; do
	check 'aws-vault ex'                            list   'exec export'
	check 'aws-vault exe'                           buffer '[aws-vault exec ]'
	check 'aws-vault exec '                         list   'demo plain'
	check 'aws-vault exec de'                       buffer '[aws-vault exec demo ]'
	check 'aws-vault export '                       list   'demo plain'
	check 'aws-vault clear pl'                      buffer '[aws-vault clear plain ]'
	check 'aws-vault login '                        list   'demo plain'
	check 'aws-vault rm de'                         buffer '[aws-vault rm demo ]'
	check 'aws-vault sso '                          list   'export list-account-roles list-accounts'
	check 'aws-vault sso ex'                        buffer '[aws-vault sso export ]'
	check 'aws-vault sso export '                   list   'demo plain'
	check 'aws-vault sso list-accounts de'          buffer '[aws-vault sso list-accounts demo ]'
	check 'aws-vault sso export --fo'               buffer '[aws-vault sso export --format ]'
	check 'aws-vault sso export --sso-session '     buffer '[aws-vault sso export --sso-session my-sso ]'
	check 'aws-vault exec --no-s'                   buffer '[aws-vault exec --no-session ]'
	check 'aws-vault exec --'                       has    '--no-session --duration --backend --parallel-safe'
	check 'aws-vault --backend=file exec de'        buffer '[aws-vault --backend=file exec demo ]'
	check 'aws-vault exec demo -- unam'             buffer '[aws-vault exec demo -- uname ]'
	check 'aws-vault exec zzzz'                     buffer '[aws-vault exec zzzz]'
	check 'aws-vault exec --zzz'                    buffer '[aws-vault exec --zzz]'
done

print
if (( failures )); then
	print -r -- "$failures of $checks checks failed"
	exit 1
fi
print -r -- "all $checks checks passed"
