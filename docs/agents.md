# AI agents

How an AI agent (Claude Code, Codex, Hermes, OpenClaw, omp or any other that
reads the [agentskills.io](https://agentskills.io) `SKILL.md` format) works
with a curral server, and what to configure on the server so it does well.

## What the agent gets

[`skills/curral`](../skills/curral) is an agent skill: instructions
(`SKILL.md`), an API reference (`references/api.md`) and a client that needs
only `sh` and `curl` (`scripts/curral.sh`; `scripts/curral.ps1` for
PowerShell). With it, an agent:

- checks the connection and, when there is none, asks the **user** to run
  `curral.sh login` in their own terminal, so the password or API key never
  goes through the conversation;
- discovers what it may query with `GET /v1/schema`, reads table and column
  comments, and the semantic documents (`/v1/docs`) written by the people who
  know the data, before writing SQL;
- validates with `dry_run`, runs one statement per request, and tells the
  user when a result was truncated, filtered or masked;
- records what it learned as a semantic document, when the user agrees and
  the policy lets the account write.

Everything the HTTP API offers is reachable through the skill, so no SDK is
required.

## Zero install: the server hands out the skill

Every running server serves the skill's documentation at `GET /skill/...`
without authentication, and `GET /` describes the server to a client that
has only its URL: version, endpoints, authentication, and the exact command
to install the skill. Give an agent nothing but the URL and it can bootstrap
itself:

```sh
curl -s https://curral.example.com/                  # where everything is, including the install command
curl -fsSL https://raw.githubusercontent.com/lucasapassos/curral/v0.8.0/skills/curral/scripts/install.sh -o install.sh
CURRAL_SKILL_REF=v0.8.0 sh install.sh ./curral       # SKILL.md, references/ and scripts/ into ./curral
./curral/scripts/curral.sh status                    # exit 5: no credentials yet
./curral/scripts/curral.sh login                     # the user, in a terminal: URL, user, password (not echoed)
```

**Documentation and code are different trust levels.** The server is
trusted with the data; a server that also shipped the scripts the agent
runs would be trusted with code execution on the agent's machine, and so
would anyone able to tamper with the connection, since the scripts read the
credentials file. So the default, `--serve-skill docs`, serves `SKILL.md`
and the API reference only and points at the scripts in the repository,
pinned to the server's version (`GET /` carries the command). For networks
without access to GitHub, `--serve-skill all` serves the scripts too, over
TLS or to loopback only, and `install.sh` then downloads from the server.
`--serve-skill off` serves neither route. See
[Security](security.md#the-agent-skill).

## Installing the skill in an agent

The same directory works in every agent that reads `SKILL.md`; only the
place differs. From a clone of the repository (or the files downloaded
above):

| Agent | Where to put `skills/curral` |
|---|---|
| Claude Code | `~/.claude/skills/curral` (personal) or `.claude/skills/curral` in the project |
| Codex | `~/.agents/skills/curral` (personal) or `.agents/skills/curral` in the repository |
| Hermes Agent | `~/.hermes/skills/curral` |
| OpenClaw | `<workspace>/skills/curral`, or `~/.openclaw/skills/curral` for every agent on the machine |
| omp | `~/.agents/skills/curral`, the shared directory it reads along with Codex |
| anything else | the agent's skills directory; the skill has no dependencies beyond `sh` and `curl` |

```sh
git clone https://github.com/lucasapassos/curral
mkdir -p ~/.claude/skills && cp -r curral/skills/curral ~/.claude/skills/curral
```

Agents with only an HTTP tool and no shell can still follow
`references/api.md`, but then the credential has to travel through the
conversation; the skill tells them to say so and to prefer a narrow API key.

## Credentials

The agent never asks for the secret. The client reads, in this order:

1. the environment: `CURRAL_URL` with `CURRAL_TOKEN` (API key or JWT) or
   `CURRAL_USER` + `CURRAL_PASSWORD`;
2. the file written by `curral.sh login`: `~/.config/curral/credentials`
   (mode 600) or `$CURRAL_CONFIG`; on Windows `%APPDATA%\curral\credentials`,
   encrypted with DPAPI.

`CURRAL_CA=/path/ca.pem` (environment or file) trusts a private CA, and one
credentials file per server (`CURRAL_CONFIG=...`) lets the agent work with
several servers.

Give each agent its own account or API key with the narrowest role that does
the job: the audit log then says which agent ran what, and the policy, row
filters and masks apply to it like to any user. An agent that is itself a
service with many end users should use [execution delegation](delegation.md)
instead, so each request runs as the end user.

## Making a server agent-friendly

The skill does its best with what the server exposes. These make the
difference between an agent that guesses and one that knows:

- **Comments.** `COMMENT ON TABLE ... IS 'one row per order'` and
  `COMMENT ON COLUMN ... IS 'amount in cents'` show up in `/v1/schema`, and
  the skill reads them before guessing from names.
- **Semantic documents** (`--docs-dir`). Notes on what tables mean, the
  right joins and filters, and sample SQL per question; the skill searches
  them with the user's question (`POST /v1/docs/search`) before writing SQL.
  Grant `docs_allow` to the people (or agents) who should write them, and
  read access to the tables they document; the example policy has a `poet`
  role for that. Every authenticated user reads every document, whatever
  tables they may query, so documents should describe meaning, not values
  or other roles' filters. With `--jev-key`, search is ranked by a model
  instead of word overlap.
- **Limits.** `--max-rows` and per-role `max_rows`/`timeout` keep an
  exploring agent from pulling a table through the API; the client reports a
  cut result with exit code 3 and the skill aggregates in SQL instead.
  `max_concurrency` per role keeps one agent from taking every slot.
- **Row filters and masks** rather than blanket denials: the agent still
  answers, from the rows it may see, and tells the user the totals are
  partial. `DESCRIBE` of such a table returns its columns; `EXPLAIN` is
  refused (the plan would show the filter).
- **Audit log** (`--audit-log`): every `X-Request-Id` the agent reports ties
  back to a line there.

## Checking the journey

`go test ./internal/server -run 'TestSkill|TestProtectedMetadata'` runs the
skill's shell client against a real server (connection set-up, every command,
exit codes) and the discovery routes. The example configuration works for a
manual run too:

```sh
CURRAL_DATA=./data curral serve --catalog examples/catalog.yaml --users examples/users.yaml \
  --policy examples/policy.rego --policy examples/roles.json \
  --policy-limits-query data.curral.limits --policy-masks-query data.curral.masks \
  --docs-dir ./data/docs --max-rows 1000
export CURRAL_URL=http://127.0.0.1:8080 CURRAL_USER=analyst CURRAL_PASSWORD=analyst-pw
skills/curral/scripts/curral.sh status && skills/curral/scripts/curral.sh schema
```

`examples/rls.yaml` names `sales.main.orders`, which must exist before the
server starts with `--row-filters` (filters are validated against the real
table): create it as `admin` first, as in the README quickstart.

See also: [API](api.md) · [Authorization](authorization.md) · [Delegation](delegation.md) · [Configuration](configuration.md)
