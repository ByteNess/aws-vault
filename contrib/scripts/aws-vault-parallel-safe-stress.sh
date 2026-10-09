#!/usr/bin/env bash

show_help() {
  cat <<'EOF'
Usage: aws-vault-parallel-safe-stress.sh [options] [MODE] --sso-start-url URL...
       aws-vault-parallel-safe-stress.sh [options] [MODE] --sso-start-urls-from-config
       aws-vault-parallel-safe-stress.sh [options] [MODE] --config FILE

Run many aws-vault processes at once against an isolated, temporary
credential store and check that they all succeed.

Given IAM Identity Center start URLs, it first finds every account and role
you can reach through them with aws-vault-collect-sso-profiles.sh, which
needs the AWS CLI v2 and jq, and tests all of them. --config tests the
profiles in an existing AWS config file instead.

Modes:
  export   Export every profile in the config in parallel (default). Checks
           that every export succeeds and that, with --parallel-safe, at most
           one SSO sign-in is started per SSO start URL.
  same     Run --runs `exec PROFILE -- true` processes for one profile in
           parallel, which races the session cache.

Options:
  --sso-start-url URL  A start URL with its region as a query parameter, e.g.
                       'https://d-1234567890.awsapps.com/start?region=us-east-1'.
                       Repeat for more start URLs.
  --sso-start-urls-from-config
                       Use every start URL in the AWS config file
                       ($AWS_CONFIG_FILE, or ~/.aws/config)
  --config FILE        AWS config file with the profiles to test, instead of
                       finding them through start URLs
  --role NAME          When finding profiles, only test roles named NAME
  --profile NAME       Profile for "same" mode (default: the first SSO profile)
  --parallel N         Concurrent aws-vault processes (default: 20)
  --runs N             Processes to run in "same" mode (default: 50)
  --aws-vault PATH     aws-vault binary to test (default: aws-vault on PATH)
  --backend NAME       file (default) or keychain (macOS only)
  --store-dir DIR      Use DIR for the file backend and keep it afterwards, so a
                       second run can reuse its cached OIDC tokens and sessions
                       (default: a temporary directory that is removed). Its
                       passphrase is $AWS_VAULT_FILE_PASSPHRASE, or
                       "aws-vault-parallel-safe-stress" if that is unset.
  --no-parallel-safe   Run without --parallel-safe, for comparison
  --max-seconds N      Fail if the run took longer than N seconds (checked
                       once every process has finished, so it does not stop
                       a hung run)
  -h, --help           Show this help

The run signs in through your browser once per SSO start URL unless the
store already holds valid OIDC tokens. Credentials are written to /dev/null.
EOF
}

usage() {
  show_help >&2
}

die() {
  printf 'aws-vault-parallel-safe-stress: %s\n' "$*" >&2
  exit 1
}

need_value() {
  if (( $2 < 2 ))
  then
    printf "Option '%s' needs a value\n" "$1" >&2
    usage
    exit 1
  fi
}

config=''
role=''
directories=()
profile=''
parallel=20
runs=50
aws_vault=aws-vault
backend='file'
store_dir=''
parallel_safe=true
max_seconds=0
mode='export'

while (( 0 < $# ))
do
  case $1 in
    -h|--help)
      show_help
      exit 0
      ;;
    --config)
      need_value "$1" "$#"
      config=${2-}
      shift 2
      ;;
    --role)
      need_value "$1" "$#"
      role=${2-}
      shift 2
      ;;
    --profile)
      need_value "$1" "$#"
      profile=${2-}
      shift 2
      ;;
    --parallel)
      need_value "$1" "$#"
      parallel=${2-}
      shift 2
      ;;
    --runs)
      need_value "$1" "$#"
      runs=${2-}
      shift 2
      ;;
    --aws-vault)
      need_value "$1" "$#"
      aws_vault=${2-}
      shift 2
      ;;
    --backend)
      need_value "$1" "$#"
      backend=${2-}
      shift 2
      ;;
    --store-dir)
      need_value "$1" "$#"
      store_dir=${2-}
      shift 2
      ;;
    --no-parallel-safe)
      parallel_safe=false
      shift
      ;;
    --max-seconds)
      need_value "$1" "$#"
      max_seconds=${2-}
      shift 2
      ;;
    export|same)
      mode=$1
      shift
      ;;
    --sso-start-url)
      need_value "$1" "$#"
      directories+=(--sso-start-url "${2-}")
      shift 2
      ;;
    --sso-start-url=*)
      directories+=(--sso-start-url "${1#--sso-start-url=}")
      shift
      ;;
    --sso-start-urls-from-config)
      directories+=(--sso-start-urls-from-config)
      shift
      ;;
    *)
      printf "Unknown argument '%s'\n" "$1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z $config ]] && (( 0 == ${#directories[@]} ))
then
  usage
  exit 1
fi
if [[ -n $config ]] && (( 0 < ${#directories[@]} ))
then
  die 'pass either --config or start URLs, not both'
fi
if [[ -n $config && ! -r $config ]]
then
  die "cannot read config file '$config'"
fi
for value in "$parallel" "$runs"
do
  if ! [[ $value =~ ^[1-9][0-9]*$ ]]
  then
    die "--parallel and --runs must be positive integers, got '$value'"
  fi
done
if ! [[ $max_seconds =~ ^[0-9]+$ ]]
then
  die "--max-seconds must be a non-negative integer, got '$max_seconds'"
fi
case $backend in
  file)
    ;;
  keychain)
    if [[ -n $store_dir ]]
    then
      die '--store-dir only applies to the file backend'
    fi
    if ! command -v security >/dev/null 2>&1
    then
      die 'the keychain backend needs macOS and the security command'
    fi
    ;;
  *)
    die "--backend must be file or keychain, got '$backend'"
    ;;
esac
if ! aws_vault=$(command -v -- "$aws_vault")
then
  die 'aws-vault binary not found; pass --aws-vault PATH'
fi

tmpdir=''
keychain=''
original_keychains=()
cleanup() {
  if [[ -n $keychain ]]
  then
    if (( 0 < ${#original_keychains[@]} ))
    then
      security list-keychains -d user -s "${original_keychains[@]}" >/dev/null 2>&1
    fi
    security delete-keychain "$keychain" >/dev/null 2>&1
  fi
  if [[ -n $tmpdir ]]
  then
    rm -rf -- "$tmpdir"
  fi
}
trap cleanup EXIT

if ! tmpdir=$(mktemp -d)
then
  die 'could not create a temporary directory'
fi
mkdir -- "$tmpdir/logs" "$tmpdir/status"

if (( 0 < ${#directories[@]} ))
then
  collect_args=(--output "$tmpdir/discovered.config")
  if [[ -n $role ]]
  then
    collect_args+=(--role "$role")
  fi
  if ! "$(dirname -- "${BASH_SOURCE[0]}")/aws-vault-collect-sso-profiles.sh" "${collect_args[@]}" "${directories[@]}"
  then
    die 'finding profiles failed; not testing an incomplete set'
  fi
  config=$tmpdir/discovered.config
fi
if ! config_dir=$(cd -- "$(dirname -- "$config")" && pwd)
then
  die "cannot resolve the directory of '$config'"
fi
config=$config_dir/$(basename -- "$config")

passphrase=$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32)
kept_store_passphrase=${AWS_VAULT_FILE_PASSPHRASE:-aws-vault-parallel-safe-stress}
unset AWS_VAULT AWS_PROFILE AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
while IFS= read -r name
do
  case $name in
    AWS_VAULT_SESSION_*|AWS_VAULT_FILE_*|AWS_VAULT_KEYCHAIN_*|AWS_VAULT_PASS_*|AWS_VAULT_PASSAGE_*|AWS_VAULT_SECRET_SERVICE_*|AWS_VAULT_OP_*|AWS_VAULT_PROTON_PASS_*|AWS_VAULT_KWALLET_*|AWS_VAULT_WINCRED_*)
      unset "$name"
      ;;
  esac
done < <(compgen -e)
export AWS_CONFIG_FILE=$config
export AWS_VAULT_BACKEND=$backend
export AWS_VAULT_PARALLEL_SAFE=$parallel_safe

if [[ $backend == file ]]
then
  if [[ -z $store_dir ]]
  then
    store_dir=$tmpdir/store
  else
    passphrase=$kept_store_passphrase
  fi
  if ! mkdir -p -- "$store_dir"
  then
    die "could not create store directory '$store_dir'"
  fi
  export AWS_VAULT_FILE_DIR=$store_dir
  export AWS_VAULT_FILE_PASSPHRASE=$passphrase
else
  while IFS= read -r line
  do
    line=${line#"${line%%[![:space:]]*}"}
    line=${line#\"}
    original_keychains+=("${line%\"}")
  done < <(security list-keychains -d user)
  keychain=$tmpdir/aws-vault-stress.keychain
  if ! security create-keychain -p "$passphrase" "$keychain" ||
    ! security set-keychain-settings -t 21600 "$keychain" ||
    ! security unlock-keychain -p "$passphrase" "$keychain" ||
    ! security list-keychains -d user -s "$keychain" "${original_keychains[@]}"
  then
    die 'could not set up a temporary keychain'
  fi
  export AWS_VAULT_KEYCHAIN_NAME=${keychain%.keychain}
fi

awk '
  function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
  /^[[:space:]]*\[/ {
    header = $0
    sub(/^[[:space:]]*\[/, "", header)
    sub(/\][[:space:]]*$/, "", header)
    header = trim(header)
    kind = ""
    if (header == "default") { kind = "profile"; name = "default" }
    else if (header ~ /^profile[[:space:]]/) { kind = "profile"; name = trim(substr(header, 8)) }
    else if (header ~ /^sso-session[[:space:]]/) { kind = "session"; name = trim(substr(header, 12)) }
    if (kind == "profile" && !(name in listed)) { listed[name] = 1; order[++count] = name }
    next
  }
  kind != "" && index($0, "=") {
    key = trim(substr($0, 1, index($0, "=") - 1))
    value = trim(substr($0, index($0, "=") + 1))
    if (kind == "profile" && key == "sso_start_url") profile_url[name] = value
    if (kind == "profile" && key == "sso_session") profile_session[name] = value
    if (kind == "session" && key == "sso_start_url") session_url[name] = value
  }
  END {
    for (i = 1; i <= count; i++) {
      p = order[i]
      url = profile_url[p]
      if (url == "" && profile_session[p] != "") url = session_url[profile_session[p]]
      if (url != "") print p "\t" url
    }
  }
' "$config" > "$tmpdir/profiles.tsv"

if [[ ! -s $tmpdir/profiles.tsv ]]
then
  die "no SSO profiles in '$config'"
fi

if [[ $mode == same ]]
then
  if [[ -z $profile ]]
  then
    IFS=$'\t' read -r profile _ < "$tmpdir/profiles.tsv"
  fi
  profile_url=$(awk -F '\t' -v p="$profile" '$1 == p { print $2; exit }' "$tmpdir/profiles.tsv")
  if [[ -z $profile_url ]]
  then
    die "no SSO profile named '$profile' in '$config'"
  fi
  for (( i = 1; i <= runs; i += 1 ))
  do
    printf '%s\t%s\n' "$profile" "$profile_url"
  done > "$tmpdir/jobs.tsv"
else
  cp -- "$tmpdir/profiles.tsv" "$tmpdir/jobs.tsv"
fi
job_count=$(wc -l < "$tmpdir/jobs.tsv" | tr -d ' ')
start_urls=$(cut -f 2 "$tmpdir/jobs.tsv" | sort -u | wc -l | tr -d ' ')

printf 'aws-vault: %s (%s)\n' "$aws_vault" "$("$aws_vault" --version 2>&1)"
printf 'mode: %s, jobs: %s, parallel: %s, parallel-safe: %s, backend: %s\n' "$mode" "$job_count" "$parallel" "$parallel_safe" "$backend"
printf 'SSO start URLs: %s\n' "$start_urls"

run_job() {
  local job=$1 profile
  IFS=$'\t' read -r profile _ < <(sed -n "${job}p" "$STRESS_JOBS")
  if [[ $STRESS_MODE == same ]]
  then
    "$STRESS_AWS_VAULT" exec "$profile" -- true > /dev/null 2> "$STRESS_LOGS/$job.err"
  else
    "$STRESS_AWS_VAULT" export --format=json "$profile" > /dev/null 2> "$STRESS_LOGS/$job.err"
  fi
  printf '%s\n' "$?" > "$STRESS_STATUS/$job"
}
export -f run_job

start=$SECONDS
for (( job = 1; job <= job_count; job += 1 ))
do
  printf '%s\n' "$job"
done | STRESS_MODE=$mode STRESS_AWS_VAULT=$aws_vault STRESS_JOBS=$tmpdir/jobs.tsv STRESS_LOGS=$tmpdir/logs STRESS_STATUS=$tmpdir/status \
  xargs -P "$parallel" -n 1 bash -c 'run_job "$1"' _
duration=$(( SECONDS - start ))

succeeded=0
failed=0
job=0
: > "$tmpdir/sign-ins.txt"
while IFS=$'\t' read -r profile url
do
  (( job += 1 ))
  status=''
  if [[ -r $tmpdir/status/$job ]]
  then
    status=$(< "$tmpdir/status/$job")
  fi
  if [[ $status == 0 ]]
  then
    (( succeeded += 1 ))
  else
    (( failed += 1 ))
    printf 'FAILED %s: %s\n' "$profile" "$(tail -n 1 "$tmpdir/logs/$job.err" 2>/dev/null)"
  fi
  count=$(grep -c 'the SSO authorization page' "$tmpdir/logs/$job.err" 2>/dev/null)
  for (( i = 0; i < ${count:-0}; i += 1 ))
  do
    printf '%s\n' "$url" >> "$tmpdir/sign-ins.txt"
  done
done < "$tmpdir/jobs.tsv"

sign_ins=$(wc -l < "$tmpdir/sign-ins.txt" | tr -d ' ')

printf 'succeeded: %s, failed: %s, SSO sign-ins started: %s, duration: %ss\n' "$succeeded" "$failed" "$sign_ins" "$duration"

problems=0
if (( 0 < failed ))
then
  (( problems += 1 ))
fi
if [[ $parallel_safe == true ]]
then
  while read -r count url
  do
    if (( 1 < count ))
    then
      printf '%s SSO sign-ins for %s: the SSO lock did not serialize them\n' "$count" "$url"
      (( problems += 1 ))
    fi
  done < <(sort "$tmpdir/sign-ins.txt" | uniq -c)
fi
if (( 0 < max_seconds && max_seconds < duration ))
then
  printf 'Took %ss, more than --max-seconds %s\n' "$duration" "$max_seconds"
  (( problems += 1 ))
fi

if (( 0 < problems ))
then
  exit 1
fi
printf 'PASS\n'
