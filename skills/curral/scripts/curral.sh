#!/bin/sh
# Minimal curral client for agents: needs only sh and curl.
#
#   curral.sh schema [database=X] [schema=Y] [table=Z]
#   curral.sh query  [-f json|csv|ndjson] [-d database] [-o file] [-m max_rows] [-p value]... "SQL"
#   curral.sh dry-run [-d database] [-p value]... "SQL"
#
# Environment: CURRAL_URL and CURRAL_TOKEN (Bearer) or CURRAL_USER + CURRAL_PASSWORD.
# -p: each value becomes $1, $2...; numbers, true, false and null are sent as
#     JSON, anything else as a string (to force a string: -p '"123"').
#
# Output: the response body on stdout (or in -o). Warnings on stderr.
# -m: at most N rows (only lowers the server's limit); the cut is a warning,
#     not an error.
# Exit code: 0 ok; 1 HTTP/network error; 2 usage; 3 result truncated by the
# server's limit (the body is incomplete); 4 error in the middle of the stream.
set -eu

die() { echo "curral: $*" >&2; exit 2; }
[ -n "${CURRAL_URL:-}" ] || die "set CURRAL_URL"
command -v curl >/dev/null || die "curl not found"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
umask 077

# Credentials go in a curl config file, not on the command line (ps).
if [ -n "${CURRAL_TOKEN:-}" ]; then
	printf 'header = "Authorization: Bearer %s"\n' "$CURRAL_TOKEN" >"$tmp/auth"
elif [ -n "${CURRAL_USER:-}" ]; then
	printf 'user = "%s:%s"\n' "$CURRAL_USER" "${CURRAL_PASSWORD:-}" | sed 's/\\/\\\\/g' >"$tmp/auth"
else
	die "set CURRAL_TOKEN or CURRAL_USER and CURRAL_PASSWORD"
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
	return 0
}

cmd=${1:-}
[ $# -gt 0 ] && shift
url=${CURRAL_URL%/}

case $cmd in
schema)
	for kv in "$@"; do
		case $kv in
		database=* | schema=* | table=*) ;;
		*) die "invalid filter: $kv (use database=, schema=, table=)" ;;
		esac
	done
	# -G + --data-urlencode builds the query string.
	OUT=- request -G "$url/v1/schema" $(for kv in "$@"; do printf -- '--data-urlencode %s ' "$kv"; done)
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
*)
	sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//' >&2
	exit 2
	;;
esac
