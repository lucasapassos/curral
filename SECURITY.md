# Security policy

curral sits between clients and your data and enforces who may read or
change what, so authorization bypasses, metadata leaks and authentication
flaws are treated as security bugs.

## Reporting a vulnerability

**Do not open a public issue.** Report it privately through GitHub:
[Security → Report a vulnerability](https://github.com/lucasapassos/curral/security/advisories/new).

Please include:
- the curral version (`curral version`) and how it is deployed;
- the catalog, policy and users files needed to reproduce, reduced to the
  minimum (never send real credentials);
- the request(s) and the response you got versus the one you expected.

You should get an acknowledgement within a few days. Once a fix is ready it
is released with a `### Security` entry in the [CHANGELOG](CHANGELOG.md) and
a GitHub security advisory, crediting the reporter unless you prefer
otherwise.

## Supported versions

Only the latest release receives security fixes.

## Scope

In scope: anything that lets a caller run a statement the policy should deny,
read rows or columns hidden by row filters or masks, learn the names or
shape of objects they cannot read, authenticate without valid credentials,
or bypass the lockout and concurrency limits.

Known, documented limitations (see [docs/security.md](docs/security.md#known-limitations))
are not vulnerabilities by themselves, but a way to make them worse is.
