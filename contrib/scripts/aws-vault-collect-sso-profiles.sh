#!/usr/bin/env bash

show_help() {
  cat <<'EOF'
Usage: aws-vault-collect-sso-profiles.sh [options] START_URL=REGION...

Write an AWS config file with a profile for every account and role reachable
through the given IAM Identity Center start URLs.

Arguments:
  START_URL=REGION     A start URL and the region of its Identity Center
                       instance, e.g.
                       https://d-1234567890.awsapps.com/start=us-east-1

Options:
  --role NAME          Only include roles named NAME (default: every role)
  --output FILE        Config file to write (default: ./aws-vault-sso-profiles.config)
  --parallel N         Concurrent list-account-roles calls (default: 10)
  -h, --help           Show this help

Start URLs without a valid token in ~/.aws/sso/cache are signed in to with
`aws sso login`, using the device code flow when AWS_VAULT_DEVICE_CODE is
true, as aws-vault does.

The config file has one profile per account and role, named
sso-<directory>-<account id>-<role>, with sso_registration_scopes set so
that aws-vault can refresh its OIDC token without a browser.
EOF
}

usage() {
  show_help >&2
}

die() {
  printf 'aws-vault-collect-sso-profiles: %s\n' "$*" >&2
  exit 1
}

role=''
output='aws-vault-sso-profiles.config'
parallel=10
directories=()

while (( 0 < $# ))
do
  case $1 in
    -h|--help)
      show_help
      exit 0
      ;;
    --role)
      role=${2-}
      shift 2
      ;;
    --output)
      output=${2-}
      shift 2
      ;;
    --parallel)
      parallel=${2-}
      shift 2
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
      printf "Expected START_URL=REGION, got '%s'\n" "$1" >&2
      usage
      exit 1
      ;;
  esac
done

if (( 0 == ${#directories[@]} ))
then
  usage
  exit 1
fi
if [[ -z $output ]]
then
  die '--output needs a file name'
fi
if ! [[ $parallel =~ ^[1-9][0-9]*$ ]]
then
  die "--parallel must be a positive integer, got '$parallel'"
fi

for cmd in aws jq
do
  if ! command -v "$cmd" >/dev/null 2>&1
  then
    die "'$cmd' is required"
  fi
done

tmpdir=''
cleanup() {
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

directory_id() {
  local start_url=$1 index=$2
  if [[ $start_url =~ /directory/(d-[0-9a-z]+) ]]
  then
    printf '%s\n' "${BASH_REMATCH[1]}"
  elif [[ $start_url =~ ^https://([^./]+)\.awsapps\.com/ ]]
  then
    printf '%s\n' "${BASH_REMATCH[1]}"
  else
    printf 'dir%s\n' "$index"
  fi
}

cached_token() {
  local start_url=$1 cache_dir=$HOME/.aws/sso/cache
  local files=("$cache_dir"/*.json)
  if [[ ! -e ${files[0]} ]]
  then
    return 1
  fi
  jq -r -s --arg url "$start_url" '
    [ .[]
      | select(.startUrl == $url and .accessToken != null)
      | {accessToken, exp: (try (.expiresAt | sub("\\.[0-9]+"; "") | sub("UTC$"; "Z") | fromdateiso8601) catch null)}
      | select(.exp != null and .exp > (now + 600))
    ]
    | sort_by(.exp) | last | .accessToken // empty
  ' "${files[@]}" 2>/dev/null
}

sso_login() {
  local start_url=$1 region=$2 login_config=$tmpdir/login.config
  {
    printf '[profile login]\n'
    printf 'sso_start_url = %s\n' "$start_url"
    printf 'sso_region = %s\n' "$region"
    printf 'sso_registration_scopes = sso:account:access\n'
  } > "$login_config"
  local login_args=(--profile login)
  case ${AWS_VAULT_DEVICE_CODE-} in
    1|t|T|true|TRUE|True)
      login_args+=(--use-device-code)
      ;;
  esac
  AWS_CONFIG_FILE=$login_config AWS_SHARED_CREDENTIALS_FILE=/dev/null \
    aws sso login "${login_args[@]}"
}

export AWS_RETRY_MODE=adaptive
export AWS_MAX_ATTEMPTS=10

list_roles() {
  local token=$1 region=$2 account_id=$3
  AWS_REGION=$region AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null \
    aws sso list-account-roles --access-token "$token" --account-id "$account_id" --output json
}
export -f list_roles

: > "$tmpdir/roles.tsv"
failures=0
index=0
for directory in "${directories[@]}"
do
  (( index += 1 ))
  start_url=${directory%=*}
  region=${directory##*=}
  dir_id=$(directory_id "$start_url" "$index")

  token=$(cached_token "$start_url")
  if [[ -z $token ]]
  then
    printf 'Signing in to %s\n' "$start_url" >&2
    if ! sso_login "$start_url" "$region"
    then
      printf 'Sign-in to %s failed, skipping it\n' "$start_url" >&2
      (( failures += 1 ))
      continue
    fi
    token=$(cached_token "$start_url")
  fi
  if [[ -z $token ]]
  then
    printf 'No token for %s in ~/.aws/sso/cache after signing in, skipping it\n' "$start_url" >&2
    (( failures += 1 ))
    continue
  fi

  if ! accounts=$(AWS_REGION=$region AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null \
    aws sso list-accounts --access-token "$token" --output json --query 'accountList[].accountId')
  then
    printf 'Listing accounts in %s failed, skipping it\n' "$start_url" >&2
    (( failures += 1 ))
    continue
  fi
  printf '%s\n' "$accounts" | jq -r '.[]' > "$tmpdir/accounts.txt"
  printf '%s: %s accounts\n' "$dir_id" "$(wc -l < "$tmpdir/accounts.txt" | tr -d ' ')" >&2

  rm -rf -- "$tmpdir/roles"
  mkdir -- "$tmpdir/roles"
  TOKEN=$token REGION=$region OUT=$tmpdir/roles xargs -P "$parallel" -n 1 bash -c '
    if list_roles "$TOKEN" "$REGION" "$1" > "$OUT/$1.json"
    then
      exit 0
    fi
    printf "Listing roles in account %s failed\n" "$1" >&2
    rm -f -- "$OUT/$1.json"
    exit 1
  ' _ < "$tmpdir/accounts.txt"

  while IFS= read -r account_id
  do
    if [[ ! -s $tmpdir/roles/$account_id.json ]]
    then
      (( failures += 1 ))
      continue
    fi
    jq -r --arg role "$role" --arg url "$start_url" --arg region "$region" --arg dir "$dir_id" '
      .roleList[]
      | select($role == "" or .roleName == $role)
      | [$dir, .accountId, .roleName, $url, $region] | @tsv
    ' "$tmpdir/roles/$account_id.json" >> "$tmpdir/roles.tsv"
  done < "$tmpdir/accounts.txt"
done

if [[ ! -s $tmpdir/roles.tsv ]]
then
  die 'no matching accounts and roles found'
fi

if ! sort -u "$tmpdir/roles.tsv" | while IFS=$'\t' read -r dir_id account_id role_name start_url region
do
  printf '[profile sso-%s-%s-%s]\n' "$dir_id" "$account_id" "${role_name//[^A-Za-z0-9_-]/_}"
  printf 'sso_start_url = %s\n' "$start_url"
  printf 'sso_region = %s\n' "$region"
  printf 'sso_account_id = %s\n' "$account_id"
  printf 'sso_role_name = %s\n' "$role_name"
  printf 'sso_registration_scopes = sso:account:access\n'
  printf 'region = %s\n\n' "$region"
done > "$output"
then
  die "could not write '$output'"
fi

printf 'Wrote %s profiles to %s\n' "$(grep -c '^\[profile ' "$output")" "$output" >&2
if (( 0 < failures ))
then
  printf '%s directories or accounts could not be listed; the config is incomplete\n' "$failures" >&2
  exit 1
fi
