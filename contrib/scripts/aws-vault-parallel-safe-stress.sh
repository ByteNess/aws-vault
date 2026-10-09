#!/usr/bin/env bash

show_help() {
  cat <<'EOF'
Usage: aws-vault-parallel-safe-stress.sh [options] [MODE] START_URL=REGION...
       aws-vault-parallel-safe-stress.sh [options] [MODE] --config FILE

Run many aws-vault processes at once against an isolated, temporary
credential store and check that they all succeed.

Given IAM Identity Center start URLs and their regions, e.g.
https://d-1234567890.awsapps.com/start=us-east-1, it first finds every
account and role you can reach through them with
aws-vault-collect-sso-profiles.sh, which needs the AWS CLI v2 and jq, and
tests all of them. --config tests the profiles in an existing AWS config
file instead.

Modes:
  export   Export every profile in the config in parallel (default). Checks
           that every export succeeds and that, with --parallel-safe, at most
           one SSO sign-in is started per SSO start URL.
  same     Run --runs `exec PROFILE -- true` processes for one profile in
           parallel, which races the session cache.

Options:
  --config FILE        AWS config file with the profiles to test, instead of
                       finding them through START_URL=REGION arguments
  --role NAME          With START_URL=REGION, only test roles named NAME
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
  --max-seconds N      Fail if the run takes longer than N seconds
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
      config=${2-}
      shift 2
      ;;
    --role)
      role=${2-}
      shift 2
      ;;
    --profile)
      profile=${2-}
      shift 2
      ;;
    --parallel)
      parallel=${2-}
      shift 2
      ;;
    --runs)
      runs=${2-}
      shift 2
      ;;
    --aws-vault)
      aws_vault=${2-}
      shift 2
      ;;
    --backend)
      backend=${2-}
      shift 2
      ;;
    --store-dir)
      store_dir=${2-}
      shift 2
      ;;
    --no-parallel-safe)
      parallel_safe=false
      shift
      ;;
    --max-seconds)
      max_seconds=${2-}
      shift 2
      ;;
    export|same)
      mode=$1
      shift
      ;;
    -*)
      printf "Unknown option '%s'\n" "$1" >&2
      usage
      exit 1
      ;;
    *=*)
      directories+=("$1")
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
  die 'pass either --config or START_URL=REGION arguments, not both'
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
config=$(cd -- "$(dirname -- "$config")" && pwd)/$(basename -- "$config")

passphrase=$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32)
unset AWS_VAULT AWS_PROFILE AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
unset AWS_VAULT_FILE_DIR AWS_VAULT_KEYCHAIN_NAME AWS_VAULT_SESSION_BACKEND
export AWS_CONFIG_FILE=$config
export AWS_VAULT_BACKEND=$backend
export AWS_VAULT_PARALLEL_SAFE=$parallel_safe

if [[ $backend == file ]]
then
  if [[ -z $store_dir ]]
  then
    store_dir=$tmpdir/store
  else
    passphrase=${AWS_VAULT_FILE_PASSPHRASE:-aws-vault-parallel-safe-stress}
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
  /^\[profile / { name = $2; sub(/\]$/, "", name); next }
  /^\[/ { name = ""; next }
  name != "" && $1 == "sso_start_url" { print name "\t" $3; name = "" }
' "$config" > "$tmpdir/profiles.tsv"

if [[ ! -s $tmpdir/profiles.tsv ]]
then
  die "no profiles with sso_start_url in '$config'"
fi

if [[ $mode == same ]]
then
  if [[ -z $profile ]]
  then
    IFS=$'\t' read -r profile _ < "$tmpdir/profiles.tsv"
  fi
  start_urls=$(awk -F '\t' -v p="$profile" '$1 == p { print $2 }' "$tmpdir/profiles.tsv" | sort -u | wc -l | tr -d ' ')
  for (( i = 1; i <= runs; i += 1 ))
  do
    printf '%s\n' "$i"
  done > "$tmpdir/jobs.txt"
  job_count=$runs
else
  cut -f 1 "$tmpdir/profiles.tsv" > "$tmpdir/jobs.txt"
  start_urls=$(cut -f 2 "$tmpdir/profiles.tsv" | sort -u | wc -l | tr -d ' ')
  job_count=$(wc -l < "$tmpdir/jobs.txt" | tr -d ' ')
fi

printf 'aws-vault: %s (%s)\n' "$aws_vault" "$("$aws_vault" --version 2>&1)"
printf 'mode: %s, jobs: %s, parallel: %s, parallel-safe: %s, backend: %s\n' "$mode" "$job_count" "$parallel" "$parallel_safe" "$backend"
printf 'SSO start URLs: %s\n' "$start_urls"

run_job() {
  local job=$1
  if [[ $STRESS_MODE == same ]]
  then
    "$STRESS_AWS_VAULT" exec "$STRESS_PROFILE" -- true > /dev/null 2> "$STRESS_LOGS/$job.err"
  else
    "$STRESS_AWS_VAULT" export --format=json "$job" > /dev/null 2> "$STRESS_LOGS/$job.err"
  fi
  printf '%s\n' "$?" > "$STRESS_STATUS/$job"
}
export -f run_job

start=$SECONDS
STRESS_MODE=$mode STRESS_PROFILE=$profile STRESS_AWS_VAULT=$aws_vault STRESS_LOGS=$tmpdir/logs STRESS_STATUS=$tmpdir/status \
  xargs -P "$parallel" -n 1 bash -c 'run_job "$1"' _ < "$tmpdir/jobs.txt"
duration=$(( SECONDS - start ))

succeeded=0
failed=0
while IFS= read -r job
do
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
    printf 'FAILED %s: %s\n' "$job" "$(tail -n 1 "$tmpdir/logs/$job.err" 2>/dev/null)"
  fi
done < "$tmpdir/jobs.txt"

sign_ins=$(cat "$tmpdir"/logs/*.err | grep -c 'the SSO authorization page')

printf 'succeeded: %s, failed: %s, SSO sign-ins started: %s, duration: %ss\n' "$succeeded" "$failed" "$sign_ins" "$duration"

problems=0
if (( 0 < failed ))
then
  (( problems += 1 ))
fi
if [[ $parallel_safe == true ]] && (( start_urls < sign_ins ))
then
  printf 'More SSO sign-ins (%s) than start URLs (%s): the SSO lock did not serialize them\n' "$sign_ins" "$start_urls"
  (( problems += 1 ))
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
