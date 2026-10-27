# Execution delegation

A trusted service, such as a portal or an internal app with its own users,
can query Curral **on behalf of** those users. The policy, row filters, masks,
limits and audit then apply to the effective identity, not to the service's
API key. This is an opt-in HTTP and Flight SQL contract; Basic, JWT and
ordinary API-key authentication keep their existing behavior.

## The delegating key

Generate a key with `curral gen-api-key` and mark it in the users file:

```yaml
api_keys:
  - name: portal
    key_sha256: <generated-sha256>
    roles: []            # never used for delegated requests
    delegation: true
    attributes:          # optional, free-form strings describing the service
      tenant: tenant-a
```

- A delegating key must name an effective identity on every data request.
  Without one, or with one Curral refuses, the request is denied: it never
  falls back to the key's own roles.
- Delegated requests are read-only (`SELECT`) even if a policy mistakenly
  allows writes. Semantic documents are read as the identity; writing them
  on its behalf needs `docs_write: true` on the key (see
  [below](#semantic-documents)).
- `attributes` reach the policy as `input.actor.attributes` and the service
  as `GET /v1/capabilities`. Use them to scope what each key may assert, for
  instance a tenant. Keys must be identifiers; values are strings of at most
  256 bytes.

`GET /v1/capabilities`, authenticated as the key without an identity, grants
no data access and returns:

```json
{"execution_context_version": 1, "delegation_required": true, "subject": "portal",
 "attributes": {"tenant": "tenant-a"}, "formats": ["json","csv","ndjson","arrow"],
 "docs": {"enabled": true, "scope": "schema", "delegated_writes": false}, "version": "..."}
```

A client should check it before sending identities and refuse servers that do
not advertise the version it implements. `docs` says whether `/v1/docs` is
served, under which `--docs-scope`, and whether this key may write documents
on behalf of its identities (`delegated_writes`).

## The execution context

Send the identity as `X-Curral-Execution-Context` (HTTP) or as the
`x-curral-execution-context` metadata key on every Flight SQL call. The value
is unpadded base64url of one UTF-8 JSON object, at most 8 KiB and 8 levels
deep:

```json
{
  "subject": "portal:tenant-a:user:42",
  "kind": "user",
  "tenant": "tenant-a",
  "page": {"id": "7", "slug": "sales-dashboard"}
}
```

- `subject` is required: a non-empty string of at most 256 bytes, without
  control characters or surrounding spaces. It becomes the effective user.
- `kind` is optional: a short string the policy can switch on.
- Everything else is the service's own and reaches the policy as given.
- `roles`, `groups` and `actor` are refused: a service cannot assert roles.
  The effective identity gets only the roles the `identities:` entries of
  the users file map to its subject. The key's roles are not inherited.

Every authenticated response carries `X-Curral-Effective-Subject` (HTTP
header, or `x-curral-effective-subject` Flight header metadata) with the
identity the request ran as, including schema and dry-run responses. Clients
should check it.

Delegation applies to `/v1/query` (dry runs included), `/v1/schema`,
`/v1/databases`, document reads (`GET /v1/docs`, `GET /v1/docs/{id}`,
`POST /v1/docs/search`), document writes with `docs_write` and Flight SQL. A
Flight handshake with a delegating key returns the same key, never a session
token: send the identity with every call.

## Semantic documents

A delegated identity reads documents like any user, and with
`--docs-scope schema` only those about tables it may query. Writes
(`POST`, `PUT`, `PATCH`, `DELETE /v1/docs`) are refused for a delegating key
unless its entry has `docs_write: true`:

```yaml
api_keys:
  - name: portal
    key_sha256: <generated-sha256>
    delegation: true
    docs_write: true
```

The write then runs as the effective identity: the docs decision
(`--policy-docs-query`) receives `input.user` (the subject), `input.roles`
(from `identities:`), `input.identity` and `input.actor`, next to the usual
`action`, `doc` and `current`; the document's `author` is the subject. The
key itself still cannot write, with or without the flag. Tie the rule to the
actor, as for queries:

```rego
docs_allow if {
  input.actor.name == "portal"
  input.identity.kind == "user"
  "poet" in input.roles
}
```

## Policy

Curral does not interpret subjects: **the policy decides what each service
may assert**. It receives:

| Input | Value |
|---|---|
| `input.user` | the effective subject |
| `input.roles` | roles mapped to that subject by `identities:` |
| `input.identity` | the whole execution context |
| `input.actor` | `{name, auth_method, attributes}` of the delegating key |

Tie every rule that allows delegated requests to the actor, so that one
service cannot pass for another service's users or for your own users:

```rego
package curral
import rego.v1

default allow := false

# Identities asserted by the portal key must belong to its tenant.
portal_identity if {
  input.actor.name == "portal"
  input.identity.tenant == input.actor.attributes.tenant
  startswith(input.user, concat(":", ["portal", input.actor.attributes.tenant, ""]))
}

allow if {
  portal_identity
  input.identity.kind in {"user", "page"}
  input.resolved
  input.statement_type == "SELECT"
  every t in input.tables { t == "sales.main.orders" }
}

row_filters := {"sales.main.orders": "region = 'north'"} if {
  input.identity.kind == "page"
}

masks := {"sales.main.orders": {"customer_email": "redact"}} if {
  input.identity.kind != "user"
}
```

Without such rules, a delegating key can assert any subject, including one
that an `identities:` entry maps to roles for your own OIDC users. Keep those
entries and your rules scoped to the actor.

## Row filters and masks

`--policy-row-filters-query` (default `data.curral.row_filters`) evaluates a
map of fully qualified tables to SQL predicates. Undefined means no extra
filter; a malformed result or an evaluation error denies the request. Policy
predicates are ANDed with the `--row-filters` file's, then applied before the
caller's own filters, joins and aggregations. This works for any caller, not
only delegated ones.

Each predicate, `--row-filters` rule and `{"sql": ...}` mask must be a single
expression: balanced parentheses outside quotes, and no `;`, comments or
dollar quotes. Anything else denies the request (or fails the load), so a
value such as `x') OR ('1'='1` cannot widen a filter. Still, do not build SQL
by interpolating `input.identity` into strings: compare against the identity
inside the SQL instead.

Filters and SQL masks can read the structured identity from the JSON session
variable `curral_identity` (empty when not delegated), for example
`json_extract_string(getvariable('curral_identity'), '$.page.slug')`, next to
`curral_user` and `curral_roles`. Session variables never outlive the request.
Schema discovery, dry runs, protections and per-user concurrency all use the
effective identity. Restrictions on views and macros over protected remote
tables keep failing closed.

## Shared keys and audit

A key without `delegation` may send `X-Curral-Caller-Context` in the same
format to record who it is calling for. It changes nothing but the audit
trail: the request runs as the key, with its roles, filters and quotas. It is
read-only when a caller context is present. The two headers are mutually
exclusive, and each may appear once.

Audit events carry the effective `user`, the delegating `actor`, the
structured `identity` (or `caller` for shared keys), the policy hash and the
request ID. A refused identity is recorded as `delegation_denied`. Parameter
values are never logged; SQL redaction and fail-closed audit keep working.

## Trust model

The delegating service is a trust boundary: whoever holds its key can assert
any identity its policy rules accept. The service is responsible for
authenticating its users and deciding what they may reach before asking
Curral. Use one key per service or tenant, TLS, rotation (`expires`) and
proper secret storage. A signed end-user token is not required by this model.
