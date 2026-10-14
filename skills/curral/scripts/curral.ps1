# Minimal curral client for agents on Windows: needs only PowerShell 5.1+ and
# curl.exe (shipped with Windows 10 1803 and later). Same commands, output and
# exit codes as curral.sh.
$usage = @'
  curral.ps1 status                              (connection check; no secrets shown)
  curral.ps1 login                               (interactive: the user runs it in a terminal)
  curral.ps1 schema [database=X] [schema=Y] [table=Z]
  curral.ps1 query  [-f json|csv|ndjson] [-d database] [-o file] [-m max_rows] [-p value]... 'SQL'
  curral.ps1 dry-run [-d database] [-p value]... 'SQL'
  curral.ps1 docs [table=X] [schema=Y] [q=TEXT] [fields=header]
  curral.ps1 search [table=X] [schema=Y] [limit=N] [fields=header] 'QUESTION'
  curral.ps1 doc ID
  curral.ps1 doc-create FILE|-
  curral.ps1 doc-update [-e etag] ID FILE|-     (replaces the content)
  curral.ps1 doc-patch  [-e etag] ID FILE|-     (JSON merge patch)
  curral.ps1 doc-delete [-e etag] ID

Run it as: powershell -NoProfile -ExecutionPolicy Bypass -File curral.ps1 ...
Quote SQL with single quotes, so PowerShell does not expand $1; inside them
a quote is doubled: 'SELECT * FROM t WHERE name = ''x'' AND id = $1'.
Windows PowerShell 5.1 drops double quotes inside arguments passed to
powershell -File: avoid "quoted" identifiers in the SQL there, and pass
documents with non-ASCII text as a FILE rather than through stdin (-).

Connection: CURRAL_URL and CURRAL_TOKEN (Bearer) or CURRAL_USER +
CURRAL_PASSWORD, from the environment or from the file written by login,
$env:CURRAL_CONFIG (default %APPDATA%\curral\credentials), where the secret is
encrypted with DPAPI for the current Windows user. Credentials in the
environment take precedence over the file.
-p: each value becomes $1, $2...; numbers, true, false and null are sent as
    JSON, anything else as a string (to force a string: -p '"123"').

Output: the response body on stdout (or in -o). Warnings on stderr.
-m: at most N rows (only lowers the server's limit); the cut is a warning,
    not an error.
Exit code: 0 ok; 1 HTTP/network error; 2 usage; 3 result truncated by the
server's limit (the body is incomplete); 4 error in the middle of the stream;
5 no connection configured.
doc, doc-create, doc-update and doc-patch print the document's ETag on
stderr; pass it with -e so the write fails (412) if someone changed it since.
'@

$ErrorActionPreference = 'Stop'
$utf8 = New-Object Text.UTF8Encoding $false

function Say([string]$msg) { [Console]::Error.WriteLine("curral: $msg") }
function Die([string]$msg) { Say $msg; exit 2 }
function Write-Utf8([string]$path, [string]$text) { [IO.File]::WriteAllText($path, $text, $utf8) }
function Resolve-Local([string]$path) { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($path) }

# Quote-JsonString: string -> JSON string literal.
function Quote-JsonString([string]$s) {
	$sb = New-Object Text.StringBuilder '"'
	foreach ($ch in $s.ToCharArray()) {
		$c = [int]$ch
		if ($c -eq 34) { [void]$sb.Append('\"') }
		elseif ($c -eq 92) { [void]$sb.Append('\\') }
		elseif ($c -eq 10) { [void]$sb.Append('\n') }
		elseif ($c -eq 13) { [void]$sb.Append('\r') }
		elseif ($c -eq 9) { [void]$sb.Append('\t') }
		elseif ($c -lt 32) { [void]$sb.Append(('\u{0:x4}' -f $c)) }
		else { [void]$sb.Append($ch) }
	}
	[void]$sb.Append('"')
	$sb.ToString()
}

function Quote-JsonParam([string]$v) {
	if ($v -ceq 'true' -or $v -ceq 'false' -or $v -ceq 'null') { return $v }
	if ($v.Length -ge 2 -and $v.StartsWith('"') -and $v.EndsWith('"')) { return $v }
	if ($v -match '^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$') { return $v }
	Quote-JsonString $v
}

# Quote-Cfg: value -> quoted string for a curl config file. Every curl option
# goes through one, so nothing passes on curl's command line (ps, and
# PowerShell 5.1's quoting of native arguments).
function Quote-Cfg([string]$s) {
	if ($s -match "[`r`n]") { Die 'line breaks are not allowed in names, headers or credentials' }
	'"' + $s.Replace('\', '\\').Replace('"', '\"') + '"'
}

function Test-Id([string]$id) { if ($id -cnotmatch '^[a-z0-9]+$') { Die "invalid document id: $id" } }

function Read-Body([string]$file) {
	$path = Join-Path $tmp 'req'
	if ($file -eq '-') { Write-Utf8 $path ([Console]::In.ReadToEnd()) }
	else { Copy-Item -LiteralPath (Resolve-Local $file) -Destination $path }
	$path
}

# Invoke-Curral: runs curl with the given config lines and handles status,
# headers and trailers. Writes the body to stdout or $out.
function Invoke-Curral([string[]]$opts, [string]$out = '-', [string]$maxrows = '') {
	$body = Join-Path $tmp 'body'
	$headers = Join-Path $tmp 'headers'
	$cfg = Join-Path $tmp 'curl'
	$lines = @('silent', 'show-error', 'write-out = "%{http_code}"',
		"output = $(Quote-Cfg $body)", "dump-header = $(Quote-Cfg $headers)") + $script:authLines + $opts
	Write-Utf8 $cfg (($lines -join "`n") + "`n")
	$status = & $curl -K $cfg
	$rc = $LASTEXITCODE
	if ($rc -ne 0) {
		# A partial body from a dropped connection is not a valid result.
		Say "network/connection failure (curl $rc); incomplete result, discard it"
		if (Test-Path $body) { [Console]::Error.WriteLine([IO.File]::ReadAllText($body, $utf8)) }
		exit 1
	}
	$hdr = @{}
	foreach ($line in [IO.File]::ReadAllLines($headers)) {
		$i = $line.IndexOf(':')
		if ($i -gt 0) { $hdr[$line.Substring(0, $i).Trim().ToLowerInvariant()] = $line.Substring($i + 1).Trim() }
	}
	$reqid = [string]$hdr['x-request-id']
	if ([int]$status -ge 400) {
		Say "HTTP $status (request $reqid)"
		$retry = [string]$hdr['retry-after']
		if ($retry) { Say "Retry-After: ${retry}s" }
		if (Test-Path $body) { [Console]::Error.WriteLine([IO.File]::ReadAllText($body, $utf8)) }
		exit 1
	}
	if ($out -eq '-') {
		# The host ends the output with its own line break.
		if (Test-Path $body) { Write-Output ([IO.File]::ReadAllText($body, $utf8) -replace '\r?\n$', '') }
	} else {
		Copy-Item -LiteralPath $body -Destination (Resolve-Local $out)
	}
	$err = [string]$hdr['x-curral-error']
	$rows = [string]$hdr['x-curral-row-count']
	$max = [string]$hdr['x-curral-max-rows']
	if ($err -eq 'row limit reached' -and $maxrows -and $max -eq $maxrows) {
		# A cut requested with -m: a sample, not a failure.
		Say "sample of $rows rows (limit requested with -m); the query has more rows"
	} elseif ($err -eq 'row limit reached') {
		Say "WARNING result TRUNCATED at $rows rows (limit $max); rows are missing: aggregate in SQL or split the query"
		exit 3
	} elseif ($err) {
		Say "ERROR in the middle of the result ($rows rows sent, request $reqid): $err"
		exit 4
	}
	if ($rows -and $out -ne '-') { Say "$rows rows in $out" }
	$tag = [string]$hdr['etag']
	if ($tag) { Say "ETag: $tag" }
}

function Get-Query([string[]]$pairs, [string[]]$keys) {
	$q = foreach ($kv in $pairs) {
		$k, $v = $kv -split '=', 2
		if ($null -eq $v -or $keys -cnotcontains $k) { Die "invalid filter: $kv (use $(($keys | ForEach-Object { "$_=" }) -join ', '))" }
		"$k=$([uri]::EscapeDataString($v))"
	}
	if ($q) { '?' + ($q -join '&') } else { '' }
}

$argv = @($args | ForEach-Object { "$_" })
$cmd = if ($argv.Count) { $argv[0] } else { '' }
$rest = @(if ($argv.Count -gt 1) { $argv[1..($argv.Count - 1)] })
$commands = 'login', 'status', 'schema', 'query', 'dry-run', 'docs', 'search', 'doc', 'doc-create', 'doc-update', 'doc-patch', 'doc-delete'
if ($commands -cnotcontains $cmd) { [Console]::Error.WriteLine($usage); exit 2 }

$curl = Get-Command curl.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $curl) { $curl = Get-Command curl -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1 }
if (-not $curl) { Die 'curl.exe not found (it ships with Windows 10 1803 and later)' }

$self = $MyInvocation.MyCommand.Path
$isWin = [Environment]::OSVersion.Platform -eq 'Win32NT'
$config = if ($env:CURRAL_CONFIG) { Resolve-Local $env:CURRAL_CONFIG }
elseif ($isWin) { Join-Path $env:APPDATA 'curral\credentials' }
else { Join-Path $HOME '.config/curral/credentials-ps' }
$loginHint = "powershell -NoProfile -ExecutionPolicy Bypass -File `"$self`" login"

$envUrl, $envToken, $envUser, $envPassword = $env:CURRAL_URL, $env:CURRAL_TOKEN, $env:CURRAL_USER, $env:CURRAL_PASSWORD

# login: asks for the connection in the user's terminal (the secret is not
# echoed) and writes it to $config, encrypted with DPAPI, so it never passes
# through an agent's command line or conversation.
if ($cmd -eq 'login') {
	if ([Console]::IsInputRedirected) { Die "login is interactive: the user must run it in their own terminal: $loginHint" }
	$newUrl = Read-Host "curral URL$(if ($envUrl) { " [$envUrl]" })"
	if (-not $newUrl) { $newUrl = $envUrl }
	if (-not $newUrl) { Die 'a URL is required' }
	$newUser = Read-Host 'User (empty to use an API key or token)'
	$secret = Read-Host -AsSecureString $(if ($newUser) { "Password for $newUser" } else { 'API key or token' })
	if ($secret.Length -eq 0) { Die 'nothing typed; the file was not changed' }
	$lines = @("CURRAL_URL=$newUrl")
	if ($newUser) { $lines += "CURRAL_USER=$newUser", "CURRAL_PASSWORD_DPAPI=$(ConvertFrom-SecureString $secret)" }
	else { $lines += "CURRAL_TOKEN_DPAPI=$(ConvertFrom-SecureString $secret)" }
	New-Item -ItemType Directory -Force -Path (Split-Path $config) | Out-Null
	Write-Utf8 "$config.tmp" (($lines -join "`n") + "`n")
	if (-not $isWin) { chmod 600 "$config.tmp" }
	Move-Item -Force -LiteralPath "$config.tmp" -Destination $config
	Say "saved to $config"
	if ($envToken -or $envUser) { Say 'warning: CURRAL_TOKEN/CURRAL_USER in this environment take precedence over the file' }
	# Check what was just saved, not the environment.
	$envUrl, $envToken, $envUser, $envPassword = '', '', '', ''
	$cmd = 'status'
}

# Fill what the environment does not set from $config.
$url, $token, $user, $password, $from = $envUrl, $envToken, $envUser, $envPassword, 'environment'
if (Test-Path -LiteralPath $config) {
	$f = @{}
	foreach ($line in [IO.File]::ReadAllLines($config)) {
		$k, $v = $line -split '=', 2
		if ($null -ne $v) { $f[$k] = $v }
	}
	# DPAPI: only the Windows user who ran login on this machine can decrypt.
	function Unprotect([string]$v) {
		if (-not $v) { return '' }
		try { [Net.NetworkCredential]::new('', (ConvertTo-SecureString $v)).Password }
		catch { Say "cannot decrypt the secret in $config (saved by another user or machine)"; Say "the user must run, in their own terminal: $loginHint"; exit 5 }
	}
	if (-not $url) { $url = $f['CURRAL_URL'] }
	if (-not $token -and -not $user) {
		$token = Unprotect $f['CURRAL_TOKEN_DPAPI']
		$user = $f['CURRAL_USER']
		$password = Unprotect $f['CURRAL_PASSWORD_DPAPI']
		$from = $config
	}
}

function Unconfigured([string]$why) {
	Say "no connection configured ($why)."
	Say "the user must run, in their own terminal: $loginHint"
	exit 5
}
if (-not $url) { Unconfigured 'no CURRAL_URL' }
$url = $url.TrimEnd('/')

if ($token) {
	$authLines = @("header = $(Quote-Cfg "Authorization: Bearer $token")")
	$auth = 'API key/token'
} elseif ($user) {
	$authLines = @("user = $(Quote-Cfg "${user}:$password")")
	$auth = "user $user"
} else {
	Unconfigured 'no CURRAL_TOKEN or CURRAL_USER'
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("curral-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
$savedEncoding = [Console]::OutputEncoding
try {
	# Without a console (some hosts) the encoding cannot change; output stays in the OEM code page.
	try { [Console]::OutputEncoding = $utf8 } catch { }
	$json = 'header = "Content-Type: application/json"'
	switch ($cmd) {
		'status' {
			if ($rest.Count) { Die 'usage: status' }
			Say "$url, $auth (from $from)"
			Invoke-Curral @("url = $(Quote-Cfg "$url/v1/databases")")
		}
		'schema' {
			$q = Get-Query $rest 'database', 'schema', 'table'
			Invoke-Curral @("url = $(Quote-Cfg "$url/v1/schema$q")")
		}
		{ $_ -in 'query', 'dry-run' } {
			$format, $database, $out, $maxrows, $params = 'json', '', '-', '', @()
			$i = 0
			while ($i -lt $rest.Count -and $rest[$i] -cmatch '^-[fdomp]$') {
				if ($i + 1 -ge $rest.Count) { Die "$($rest[$i]) needs a value" }
				$v = $rest[$i + 1]
				switch -CaseSensitive ($rest[$i]) {
					'-f' { $format = $v }
					'-d' { $database = $v }
					'-o' { $out = $v }
					'-m' { if ($v -notmatch '^[0-9]+$') { Die '-m needs an integer' }; $maxrows = $v }
					'-p' { $params += Quote-JsonParam $v }
				}
				$i += 2
			}
			if ($rest.Count - $i -ne 1) { Die 'pass the SQL as a single argument, after the options' }
			$req = '{"sql":' + (Quote-JsonString $rest[$i]) + ',"format":' + (Quote-JsonString $format)
			if ($params.Count) { $req += ',"params":[' + ($params -join ',') + ']' }
			if ($database) { $req += ',"database":' + (Quote-JsonString $database) }
			if ($maxrows) { $req += ',"max_rows":' + $maxrows }
			if ($cmd -eq 'dry-run') { $req += ',"dry_run":true' }
			$path = Join-Path $tmp 'req'
			Write-Utf8 $path ($req + '}')
			Invoke-Curral @($json, "data-binary = $(Quote-Cfg "@$path")", "url = $(Quote-Cfg "$url/v1/query")") $out $maxrows
		}
		'docs' {
			$q = Get-Query $rest 'table', 'schema', 'q', 'fields'
			Invoke-Curral @("url = $(Quote-Cfg "$url/v1/docs$q")")
		}
		'search' {
			if ($rest.Count -lt 1) { Die 'usage: search [table=X] [schema=Y] [limit=N] [fields=header] "QUESTION"' }
			$req = '{"q":' + (Quote-JsonString $rest[-1])
			foreach ($kv in @(if ($rest.Count -gt 1) { $rest[0..($rest.Count - 2)] })) {
				$k, $v = $kv -split '=', 2
				if ($null -ne $v -and $k -cin 'table', 'schema', 'fields') { $req += ',"' + $k + '":' + (Quote-JsonString $v) }
				elseif ($null -ne $v -and $k -ceq 'limit') {
					if ($v -notmatch '^[0-9]+$') { Die 'limit= needs an integer' }
					$req += ',"limit":' + $v
				}
				else { Die "invalid option: $kv (use table=, schema=, limit=, fields=header; the question goes last)" }
			}
			$path = Join-Path $tmp 'req'
			Write-Utf8 $path ($req + '}')
			Invoke-Curral @($json, "data-binary = $(Quote-Cfg "@$path")", "url = $(Quote-Cfg "$url/v1/docs/search")")
		}
		'doc' {
			if ($rest.Count -ne 1) { Die 'usage: doc ID' }
			Test-Id $rest[0]
			Invoke-Curral @("url = $(Quote-Cfg "$url/v1/docs/$($rest[0])")")
		}
		'doc-create' {
			if ($rest.Count -ne 1) { Die 'usage: doc-create FILE|-' }
			$path = Read-Body $rest[0]
			Invoke-Curral @($json, "data-binary = $(Quote-Cfg "@$path")", "url = $(Quote-Cfg "$url/v1/docs")")
		}
		{ $_ -in 'doc-update', 'doc-patch', 'doc-delete' } {
			$opts = @()
			if ($rest.Count -ge 2 -and $rest[0] -ceq '-e') {
				$opts += "header = $(Quote-Cfg "If-Match: $($rest[1])")"
				$rest = @($rest | Select-Object -Skip 2)
			}
			Test-Id $(if ($rest.Count) { $rest[0] } else { '' })
			if ($cmd -eq 'doc-delete') {
				if ($rest.Count -ne 1) { Die 'usage: doc-delete [-e etag] ID' }
				$opts += 'request = "DELETE"'
			} else {
				if ($rest.Count -ne 2) { Die "usage: $cmd [-e etag] ID FILE|-" }
				$method, $ctype = 'PUT', 'application/json'
				if ($cmd -eq 'doc-patch') { $method, $ctype = 'PATCH', 'application/merge-patch+json' }
				$path = Read-Body $rest[1]
				$opts += "request = `"$method`"", "header = `"Content-Type: $ctype`"", "data-binary = $(Quote-Cfg "@$path")"
			}
			Invoke-Curral ($opts + "url = $(Quote-Cfg "$url/v1/docs/$($rest[0])")")
		}
	}
} finally {
	[Console]::OutputEncoding = $savedEncoding
	Remove-Item -Recurse -Force -LiteralPath $tmp -ErrorAction SilentlyContinue
}
exit 0
