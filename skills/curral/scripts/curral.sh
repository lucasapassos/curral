#!/bin/sh
# Minimal curral client for agents: needs only sh and curl.
#
#   curral.sh status                              (connection check; no secrets shown)
#   curral.sh login                               (interactive: the user runs it in a terminal)
#   curral.sh schema [database=X] [schema=Y] [table=Z]
#   curral.sh query  [-f json|csv|ndjson] [-d database] [-o file] [-m max_rows] [-p value]... "SQL"
#   curral.sh dry-run [-d database] [-p value]... "SQL"
#   curral.sh docs [table=X] [schema=Y] [q=TEXT] [fields=header]
#   curral.sh search [table=X] [schema=Y] [limit=N] [fields=header] "QUESTION"
#   curral.sh doc ID
#   curral.sh doc-create FILE|-
#   curral.sh doc-update [-e etag] ID FILE|-     (replaces the content)
#   curral.sh doc-patch  [-e etag] ID FILE|-     (JSON merge patch)
#   curral.sh doc-delete [-e etag] ID
#
# Connection: CURRAL_URL and CURRAL_TOKEN (Bearer) or CURRAL_USER +
# CURRAL_PASSWORD, from the environment or from the file written by login,
# $CURRAL_CONFIG (default ~/.config/curral/credentials, KEY=value lines).
# Credentials in the environment take precedence over the file.
# -p: each value becomes $1, $2...; numbers, true, false and null are sent as
#     JSON, anything else as a string (to force a string: -p '"123"').
#
# Output: the response body on stdout (or in -o). Warnings on stderr.
# -m: at most N rows (only lowers the server's limit); the cut is a warning,
#     not an error.
# Exit code: 0 ok; 1 HTTP/network error; 2 usage; 3 result truncated by the
# server's limit (the body is incomplete); 4 error in the middle of the stream;
# 5 no connection configured.
# doc, doc-create, doc-update and doc-patch print the document's ETag on
# stderr; pass it with -e so the write fails (412) if someone changed it since.
set -eu

die() { echo "curral: $*" >&2; exit 2; }
command -v curl >/dev/null || die "curl not found"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
umask 077

cmd=${1:-}
[ $# -gt 0 ] && shift
case $cmd in
login | status | schema | query | dry-run | docs | search | doc | doc-create | doc-update | doc-patch | doc-delete) ;;
*)
	sed -n '2,31p' "$0" | sed 's/^# \{0,1\}//' >&2
	exit 2
	;;
esac
self=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
config=${CURRAL_CONFIG:-${XDG_CONFIG_HOME:-${HOME:-}/.config}/curral/credentials}

# login: asks for the connection in the user's terminal (the password is not
# echoed) and writes it to $config, so it never passes through an agent's
# command line or conversation.
if [ "$cmd" = login ]; then
	[ -t 0 ] || die "login is interactive: the user must run it in their own terminal: $self login"
	trap 'stty echo 2>/dev/null; rm -rf "$tmp"' EXIT
	trap 'exit 130' INT TERM
	printf 'curral URL%s: ' "${CURRAL_URL:+ [$CURRAL_URL]}" >&2
	read -r new_url
	new_url=${new_url:-${CURRAL_URL:-}}
	[ -n "$new_url" ] || die "a URL is required"
	printf 'User (empty to use an API key or token): ' >&2
	read -r new_user
	stty -echo
	if [ -n "$new_user" ]; then printf 'Password for %s: ' "$new_user" >&2; else printf 'API key or token: ' >&2; fi
	read -r secret
	stty echo
	echo >&2
	[ -n "$secret" ] || die "nothing typed; the file was not changed"
	mkdir -p "$(dirname "$config")"
	{
		printf 'CURRAL_URL=%s\n' "$new_url"
		if [ -n "$new_user" ]; then
			printf 'CURRAL_USER=%s\nCURRAL_PASSWORD=%s\n' "$new_user" "$secret"
		else
			printf 'CURRAL_TOKEN=%s\n' "$secret"
		fi
	} >"$config.tmp"
	chmod 600 "$config.tmp"
	mv "$config.tmp" "$config"
	echo "curral: saved to $config" >&2
	[ -z "${CURRAL_TOKEN:-}${CURRAL_USER:-}" ] ||
		echo "curral: warning: CURRAL_TOKEN/CURRAL_USER in this environment take precedence over the file" >&2
	CURRAL_URL='' CURRAL_TOKEN='' CURRAL_USER='' CURRAL_PASSWORD='' CURRAL_CONFIG=$config sh "$self" status >/dev/null
	exit
fi

# Fill what the environment does not set from $config. Parsed, not sourced:
# values are literal, without quotes.
from=environment
if [ -f "$config" ]; then
	case $(ls -lLd -- "$config") in
	-???------*) ;;
	*) echo "curral: warning: $config is readable by other users; run: chmod 600 $config" >&2 ;;
	esac
	f_url='' f_token='' f_user='' f_password=''
	while IFS= read -r line || [ -n "$line" ]; do
		case $line in
		CURRAL_URL=*) f_url=${line#*=} ;;
		CURRAL_TOKEN=*) f_token=${line#*=} ;;
		CURRAL_USER=*) f_user=${line#*=} ;;
		CURRAL_PASSWORD=*) f_password=${line#*=} ;;
		esac
	done <"$config"
	CURRAL_URL=${CURRAL_URL:-$f_url}
	if [ -z "${CURRAL_TOKEN:-}${CURRAL_USER:-}" ]; then
		CURRAL_TOKEN=$f_token CURRAL_USER=$f_user CURRAL_PASSWORD=$f_password
		from=$config
	fi
fi

unconfigured() {
	echo "curral: no connection configured ($1)." >&2
	echo "curral: the user must run, in their own terminal: $self login" >&2
	exit 5
}
[ -n "${CURRAL_URL:-}" ] || unconfigured "no CURRAL_URL"

# Credentials go in a curl config file, not on the command line (ps).
cfg_quote() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
if [ -n "${CURRAL_TOKEN:-}" ]; then
	printf 'header = "Authorization: Bearer %s"\n' "$(cfg_quote "$CURRAL_TOKEN")" >"$tmp/auth"
	auth="API key/token"
elif [ -n "${CURRAL_USER:-}" ]; then
	printf 'user = "%s:%s"\n' "$(cfg_quote "$CURRAL_USER")" "$(cfg_quote "${CURRAL_PASSWORD:-}")" >"$tmp/auth"
	auth="user $CURRAL_USER"
else
	unconfigured "no CURRAL_TOKEN or CURRAL_USER"
fi

# json_string: stdin -> escaped JSON string.
json_string() {
	awk 'BEGIN { ORS = ""; print "\"" }
	{
		if (NR > 1) print "\\n"
		gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); gsub(/\t/, "\\t"); gsub(/\r/, "\\r")
		print
	}
	END { print "\"" }'
}

json_param() {
	case $1 in
	true | false | null) printf '%s' "$1" ;;
	\"*\") printf '%s' "$1" ;;
	*)
		if printf '%s' "$1" | grep -Eq '^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$'; then
			printf '%s' "$1"
		else
			printf '%s' "$1" | json_string
		fi
		;;
	esac
}

nl='
'
cr=$(printf '\r')

check_id() {
	case $1 in
	"" | *[!a-z0-9]*) die "invalid document id: $1" ;;
	esac
}

# request: runs curl and handles status, headers and trailers.
request() {
	out=${OUT:--}
	set +e
	status=$(curl -sS -K "$tmp/auth" -D "$tmp/headers" -o "$tmp/body" -w '%{http_code}' "$@")
	rc=$?
	set -e
	if [ "$rc" -ne 0 ]; then
		# A partial body from a dropped connection is not a valid result.
		echo "curral: network/connection failure (curl $rc); incomplete result, discard it" >&2
		[ -s "$tmp/body" ] && cat "$tmp/body" >&2
		exit 1
	fi
	hdr() { tr -d '\r' <"$tmp/headers" | awk -v k="$1" 'BEGIN{IGNORECASE=1} tolower($0) ~ "^" tolower(k) ":" {sub(/^[^:]*: */, ""); v=$0} END{print v}'; }
	reqid=$(hdr X-Request-Id)
	if [ "$status" -ge 400 ]; then
		echo "curral: HTTP $status (request $reqid)" >&2
		retry=$(hdr Retry-After)
		[ -n "$retry" ] && echo "curral: Retry-After: ${retry}s" >&2
		cat "$tmp/body" >&2
		echo >&2
		exit 1
	fi
	if [ "$out" = - ]; then cat "$tmp/body"; else cp "$tmp/body" "$out"; fi
	err=$(hdr X-Curral-Error)
	rows=$(hdr X-Curral-Row-Count)
	max=$(hdr X-Curral-Max-Rows)
	if [ "$err" = "row limit reached" ] && [ -n "${maxrows:-}" ] && [ "$max" = "$maxrows" ]; then
		# A cut requested with -m: a sample, not a failure.
		echo "curral: sample of $rows rows (limit requested with -m); the query has more rows" >&2
	elif [ "$err" = "row limit reached" ]; then
		echo "curral: WARNING result TRUNCATED at $rows rows (limit $max); rows are missing: aggregate in SQL or split the query" >&2
		exit 3
	elif [ -n "$err" ]; then
		echo "curral: ERROR in the middle of the result ($rows rows sent, request $reqid): $err" >&2
		exit 4
	fi
	[ -n "$rows" ] && [ "$out" != - ] && echo "curral: $rows rows in $out" >&2
	tag=$(hdr ETag)
	[ -n "$tag" ] && echo "curral: ETag: $tag" >&2
	return 0
}

url=${CURRAL_URL%/}

case $cmd in
status)
	[ $# -eq 0 ] || die "usage: status"
	echo "curral: $url, $auth (from $from)" >&2
	OUT=- request "$url/v1/databases"
	;;
schema)
	for kv in "$@"; do
		case $kv in
		database=* | schema=* | table=*) ;;
		*) die "invalid filter: $kv (use database=, schema=, table=)" ;;
		esac
	done
	# Each filter becomes "--data-urlencode k=v" as separate quoted words: a
	# value with spaces must never turn into curl options (-x would leak the
	# credentials to a proxy).
	for kv in "$@"; do
		set -- "$@" --data-urlencode "$kv"
		shift
	done
	OUT=- request -G "$@" "$url/v1/schema"
	;;
query | dry-run)
	format=json database="" OUT=- params="" maxrows=""
	while getopts f:d:o:m:p: opt; do
		case $opt in
		f) format=$OPTARG ;;
		d) database=$OPTARG ;;
		o) OUT=$OPTARG ;;
		m) case $OPTARG in *[!0-9]* | "") die "-m needs an integer" ;; esac; maxrows=$OPTARG ;;
		p) params="${params:+$params,}$(json_param "$OPTARG")" ;;
		*) die "invalid option" ;;
		esac
	done
	shift $((OPTIND - 1))
	[ $# -eq 1 ] || die "pass the SQL as a single argument, after the options"
	sql=$(printf '%s' "$1" | json_string)
	{
		printf '{"sql":%s,"format":"%s"' "$sql" "$format"
		[ -n "$params" ] && printf ',"params":[%s]' "$params"
		[ -n "$database" ] && printf ',"database":%s' "$(printf '%s' "$database" | json_string)"
		[ -n "$maxrows" ] && printf ',"max_rows":%s' "$maxrows"
		[ "$cmd" = dry-run ] && printf ',"dry_run":true'
		printf '}'
	} >"$tmp/req"
	OUT=$OUT request -H 'Content-Type: application/json' --data-binary "@$tmp/req" "$url/v1/query"
	;;
docs)
	for kv in "$@"; do
		case $kv in
		table=* | schema=* | q=* | fields=*) ;;
		*) die "invalid filter: $kv (use table=, schema=, q=, fields=header)" ;;
		esac
	done
	# Each filter becomes "--data-urlencode k=v" as separate quoted words: a
	# value with spaces must never turn into curl options (-x would leak the
	# credentials to a proxy).
	for kv in "$@"; do
		set -- "$@" --data-urlencode "$kv"
		shift
	done
	OUT=- request -G "$@" "$url/v1/docs"
	;;
search)
	[ $# -ge 1 ] || die "usage: search [table=X] [schema=Y] [limit=N] [fields=header] \"QUESTION\""
	body=""
	while [ $# -gt 1 ]; do
		case $1 in
		table=* | schema=* | fields=*)
			body="$body,\"${1%%=*}\":$(printf '%s' "${1#*=}" | json_string)" ;;
		limit=*)
			case ${1#limit=} in *[!0-9]* | "") die "limit= needs an integer" ;; esac
			body="$body,\"limit\":${1#limit=}" ;;
		*) die "invalid option: $1 (use table=, schema=, limit=, fields=header; the question goes last)" ;;
		esac
		shift
	done
	printf '{"q":%s%s}' "$(printf '%s' "$1" | json_string)" "$body" >"$tmp/req"
	OUT=- request -H 'Content-Type: application/json' --data-binary "@$tmp/req" "$url/v1/docs/search"
	;;
doc)
	[ $# -eq 1 ] || die "usage: doc ID"
	check_id "$1"
	OUT=- request "$url/v1/docs/$1"
	;;
doc-create)
	[ $# -eq 1 ] || die "usage: doc-create FILE|-"
	OUT=- request -H 'Content-Type: application/json' --data-binary "@$1" "$url/v1/docs"
	;;
doc-update | doc-patch | doc-delete)
	etag=""
	while getopts e: opt; do
		case $opt in
		e) case $OPTARG in *"$nl"* | *"$cr"*) die "-e: invalid ETag" ;; esac; etag=$OPTARG ;;
		*) die "invalid option" ;;
		esac
	done
	shift $((OPTIND - 1))
	check_id "${1:-}"
	if [ "$cmd" = doc-delete ]; then
		[ $# -eq 1 ] || die "usage: doc-delete [-e etag] ID"
		set -- -X DELETE "$url/v1/docs/$1"
	else
		[ $# -eq 2 ] || die "usage: $cmd [-e etag] ID FILE|-"
		method=PUT ctype=application/json
		[ "$cmd" = doc-patch ] && method=PATCH ctype=application/merge-patch+json
		set -- -X "$method" -H "Content-Type: $ctype" --data-binary "@$2" "$url/v1/docs/$1"
	fi
	[ -n "$etag" ] && set -- -H "If-Match: $etag" "$@"
	OUT=- request "$@"
	;;
esac
