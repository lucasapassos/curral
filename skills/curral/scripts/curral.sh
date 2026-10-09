#!/bin/sh
# Cliente mínimo do curral para agentes: só precisa de sh e curl.
#
#   curral.sh schema [database=X] [schema=Y] [table=Z]
#   curral.sh query  [-f json|csv|ndjson] [-d database] [-o arquivo] [-m max_linhas] [-p valor]... "SQL"
#   curral.sh dry-run [-d database] [-p valor]... "SQL"
#
# Ambiente: CURRAL_URL e CURRAL_TOKEN (Bearer) ou CURRAL_USER + CURRAL_PASSWORD.
# -p: cada valor vira $1, $2...; números, true, false e null vão como JSON,
#     o resto como string (para forçar string: -p '"123"').
#
# Saída: o corpo da resposta no stdout (ou em -o). Avisos em stderr.
# -m: no máximo N linhas (só reduz o limite do servidor); o corte vira aviso,
#     não erro.
# Código de saída: 0 ok; 1 erro HTTP/rede; 2 uso; 3 resultado truncado pelo
# limite do servidor (o corpo está incompleto); 4 erro no meio do stream.
set -eu

die() { echo "curral: $*" >&2; exit 2; }
[ -n "${CURRAL_URL:-}" ] || die "defina CURRAL_URL"
command -v curl >/dev/null || die "curl não encontrado"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
umask 077

# Credenciais num arquivo de config do curl, não na linha de comando (ps).
if [ -n "${CURRAL_TOKEN:-}" ]; then
	printf 'header = "Authorization: Bearer %s"\n' "$CURRAL_TOKEN" >"$tmp/auth"
elif [ -n "${CURRAL_USER:-}" ]; then
	printf 'user = "%s:%s"\n' "$CURRAL_USER" "${CURRAL_PASSWORD:-}" | sed 's/\\/\\\\/g' >"$tmp/auth"
else
	die "defina CURRAL_TOKEN ou CURRAL_USER e CURRAL_PASSWORD"
fi

# json_string: stdin -> string JSON com escape.
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

# request: executa curl e trata status, headers e trailers.
request() {
	out=${OUT:--}
	set +e
	status=$(curl -sS -K "$tmp/auth" -D "$tmp/headers" -o "$tmp/body" -w '%{http_code}' "$@")
	rc=$?
	set -e
	if [ "$rc" -ne 0 ]; then
		# Corpo parcial de uma conexão derrubada não é resultado válido.
		echo "curral: falha de rede/conexão (curl $rc); resultado incompleto, descarte-o" >&2
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
		# Corte pedido com -m: uma amostra, não uma falha.
		echo "curral: amostra de $rows linhas (limite pedido com -m); a consulta tem mais linhas" >&2
	elif [ "$err" = "row limit reached" ]; then
		echo "curral: AVISO resultado TRUNCADO em $rows linhas (limite $max); faltam linhas: agregue no SQL ou divida a consulta" >&2
		exit 3
	elif [ -n "$err" ]; then
		echo "curral: ERRO no meio do resultado ($rows linhas enviadas, request $reqid): $err" >&2
		exit 4
	fi
	[ -n "$rows" ] && [ "$out" != - ] && echo "curral: $rows linhas em $out" >&2
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
		*) die "filtro inválido: $kv (use database=, schema=, table=)" ;;
		esac
	done
	# -G + --data-urlencode monta a query string.
	OUT=- request -G "$url/v1/schema" $(for kv in "$@"; do printf -- '--data-urlencode %s ' "$kv"; done)
	;;
query | dry-run)
	format=json database="" OUT=- params="" maxrows=""
	while getopts f:d:o:m:p: opt; do
		case $opt in
		f) format=$OPTARG ;;
		d) database=$OPTARG ;;
		o) OUT=$OPTARG ;;
		m) case $OPTARG in *[!0-9]* | "") die "-m precisa de um inteiro" ;; esac; maxrows=$OPTARG ;;
		p) params="${params:+$params,}$(json_param "$OPTARG")" ;;
		*) die "opção inválida" ;;
		esac
	done
	shift $((OPTIND - 1))
	[ $# -eq 1 ] || die "passe o SQL como um único argumento, depois das opções"
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
