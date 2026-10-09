# Deploying on a server with Docker Compose

This guide runs curral on a remote server, serving a **Cloudflare R2 Data
Catalog** (Iceberg), with automatic HTTPS from Caddy (Let's Encrypt) and an
unrestricted `admin` user.

```
client ──HTTPS:443──▶ caddy ──HTTP:8080 (internal network)──▶ curral ──▶ R2 Data Catalog
```

- **Caddy:** a reverse proxy that obtains and renews the TLS certificate on
  its own and forwards requests to curral. It is the only service that
  publishes ports (80 and 443).
- **curral:** not exposed to the internet, only to the compose's internal
  network.

In this guide, values in `<...>` are yours. None of them should go into git.

## Prerequisites

- **Official Docker**, installed from Docker's repository (`get.docker.com`).
  **Do not use the snap Docker**: its confinement breaks container DNS and
  port publishing, and blocks running the binary
  (`exec /usr/local/bin/curral: operation not permitted`). See
  [Troubleshooting](#troubleshooting).
- **A domain** (e.g. `curral.example.com`) with an A/AAAA record pointing to
  the server. If the DNS is on Cloudflare, leave the proxy off (grey cloud) so
  Let's Encrypt can validate.
- **Ports 80 and 443** free on the host and open for inbound traffic
  (provider firewall / security group).
- **On R2:** a bucket with Data Catalog enabled and an API token with R2 Data
  Catalog and R2 Storage permissions. If access should be read-only, use a
  read-only token.

```sh
which docker            # must be /usr/bin/docker, not /snap/bin/docker
```

## 1. Layout

```
~/curral/
├── .env                 # credentials and domain (chmod 600)
├── docker-compose.yml
├── Caddyfile
└── config/              # mounted read-only at /etc/curral
    ├── catalog.yaml
    ├── users.yaml
    └── policy.rego
```

```sh
mkdir -p ~/curral/config && cd ~/curral
```

> Create the files with the heredocs below (`cat > file <<'EOF'`). Copying a
> markdown block into an editor often brings the ```` ```yaml ```` line along
> with it, which breaks parsing (`rego_parse_error: package expected`).

## 2. `.env`

The values are in the bucket's Data Catalog settings, in the R2 dashboard.

```sh
cat > .env <<'EOF'
CURRAL_DOMAIN=<curral.example.com>
R2_CATALOG_URI=https://catalog.cloudflarestorage.com/<account_id>/<bucket>
R2_WAREHOUSE=<account_id>_<bucket>
R2_TOKEN=<cloudflare-api-token>
R2_SCHEMA=<namespace>
R2_ALLOWED_PATH=s3://<bucket>/
R2_CACHE_TTL=30s
EOF
chmod 600 .env
```

| Variable | |
|---|---|
| `R2_CATALOG_URI` | the Data Catalog's "Catalog URI" |
| `R2_WAREHOUSE` | the Data Catalog's "Warehouse name" |
| `R2_TOKEN` | Cloudflare API token |
| `R2_SCHEMA` | Iceberg namespace used for unqualified names |
| `R2_ALLOWED_PATH` | storage prefix of the tables. With external access off, it is the only remote path allowed |
| `R2_CACHE_TTL` | catalog metadata cache; commits by other writers may take this long to show up |

## 3. Catalog

```sh
cat > config/catalog.yaml <<'EOF'
extensions: [httpfs, avro, iceberg]

secrets:
  - name: r2_catalog
    type: iceberg
    params:
      TOKEN: ${R2_TOKEN}

databases:
  - name: lake
    path: ${R2_WAREHOUSE}
    schema: ${R2_SCHEMA:-default}
    cache_ttl: ${R2_CACHE_TTL:-0s}
    options:
      TYPE: iceberg
      SECRET: r2_catalog
      ENDPOINT: ${R2_CATALOG_URI}

default: lake
EOF
```

curral expands the `${...}` references from the container's environment
variables, so the token is not stored in this file. See
[Configuration](../docs/configuration.md) for every catalog option.

## 4. Admin user

Generate a strong password and its bcrypt hash:

```sh
openssl rand -base64 24                                        # keep it in a password manager
docker run --rm -it lucasapassos/curral:v0.4.0 hash-password   # type the password; prints the hash
```

```sh
cat > config/users.yaml <<'EOF'
users:
  - name: admin
    password_hash: "<bcrypt hash generated above>"
    roles: [admin]
EOF
```

The file stores only the hash, never the password.

## 5. Policy

The admin can do anything:

```sh
cat > config/policy.rego <<'EOF'
package curral

import rego.v1

default allow := false

allow if "admin" in input.roles
EOF
```

**Read-only:** to let the admin only read, replace the rule with:

```rego
allow if {
	"admin" in input.roles
	input.statement_type in {"SELECT", "EXPLAIN"}
}
```

Since `--row-filters`, `--policy-masks-query` and `--policy-limits-query` are
not passed, there are no row filters, column masks or per-role limits. Only
the global limits from the compose file apply. For roles with restrictions,
see `examples/policy.rego`, `examples/roles.r2.json` and
[Authorization](../docs/authorization.md).

**Permissions:** the container runs as uid 65532, which must be able to read
the files:

```sh
sudo chown -R 65532:65532 config && sudo chmod 600 config/*
```

## 6. `Caddyfile`

```sh
cat > Caddyfile <<'EOF'
{$CURRAL_DOMAIN} {
	reverse_proxy curral:8080
	header {
		Strict-Transport-Security "max-age=31536000"
		-Server
	}
}
EOF
```

`{$CURRAL_DOMAIN}` comes from `.env`.

## 7. `docker-compose.yml`

```sh
cat > docker-compose.yml <<'EOF'
services:
  curral:
    image: lucasapassos/curral:v0.4.0
    environment:
      CURRAL_CATALOG: /etc/curral/catalog.yaml
      CURRAL_USERS: /etc/curral/users.yaml
      CURRAL_POLICY: /etc/curral/policy.rego
      CURRAL_ALLOWED_PATH: ${R2_ALLOWED_PATH:?}
      CURRAL_MAX_CONCURRENCY: 8
      CURRAL_MEMORY_LIMIT: 2GB
      CURRAL_QUERY_TIMEOUT: 600s
      CURRAL_AUDIT_LOG: /var/log/curral/audit.jsonl
      CURRAL_TRUSTED_PROXY: 172.31.247.10      # only Caddy may set X-Forwarded-For
      R2_CATALOG_URI: ${R2_CATALOG_URI:?}
      R2_WAREHOUSE: ${R2_WAREHOUSE:?}
      R2_TOKEN: ${R2_TOKEN:?}
      R2_SCHEMA: ${R2_SCHEMA:?}
      R2_CACHE_TTL: ${R2_CACHE_TTL:-30s}
    volumes:
      - ./config:/etc/curral:ro
      - audit:/var/log/curral
    read_only: true
    tmpfs:
      - /var/lib/curral/tmp:uid=65532,gid=65532,mode=0700
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    mem_limit: 3g
    restart: unless-stopped
    networks: [curral]

  caddy:
    image: caddy:2
    ports: ["80:80", "443:443"]
    environment:
      CURRAL_DOMAIN: ${CURRAL_DOMAIN:?}
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
    depends_on: [curral]
    restart: unless-stopped
    networks:
      curral:
        ipv4_address: 172.31.247.10

networks:
  curral:
    ipam:
      config:
        - subnet: 172.31.247.0/24

volumes:
  audit:
  caddy_data:
EOF
```

- **Fixed Caddy IP:** `CURRAL_TRUSTED_PROXY` trusts `X-Forwarded-For` only
  when it comes from Caddy's IP. Never trust the whole subnet, because it
  includes the Docker gateway. See
  [Authentication](../docs/authentication.md) for how the client IP is
  resolved.
- **Subnet:** if `172.31.247.0/24` collides with a local network, change the
  subnet and Caddy's IP in both places.
- **Version:** pin the image tag (`v0.4.0`) and upgrade on purpose, not with
  `latest`.

## 8. Start

```sh
docker compose up -d
docker compose ps                  # both "Up"; caddy on 0.0.0.0:80 and :443
docker compose logs -f caddy       # wait for "certificate obtained successfully"
docker compose logs -f curral      # wait for the lake ATTACH and the listen on :8080
```

## 9. Test

From your machine:

```sh
curl -u admin https://<curral.example.com>/v1/query \
  -d '{"sql":"SELECT count(*) FROM <table>","format":"csv"}'
```

With `-u admin` and no password, curl prompts for the password in the
terminal, so it does not end up in the shell history. With the `curral`
client:

```sh
export CURRAL_URL=https://<curral.example.com> CURRAL_USER=admin
read -rs CURRAL_PASSWORD && export CURRAL_PASSWORD
curral query "SELECT * FROM <table> LIMIT 10"
```

See [API](../docs/api.md) for the request format and the client options.

## Operations

| Task | Command |
|---|---|
| Change a password / edit users or the policy | edit `config/*` and run `docker compose kill -s HUP curral` (no restart) |
| Change the catalog or `.env` | `docker compose up -d` (recreates the container) |
| Upgrade | change the tag in the compose file and run `docker compose up -d` |
| Audit log | `docker compose exec` does not work (the image has no shell); read the volume: `docker run --rm -v curral_audit:/a alpine tail /a/audit.jsonl` |
| Logs | `docker compose logs -f curral` |

In the audit log, SQL literals are redacted and passwords never appear. See
[Security](../docs/security.md) for the audit format and
[Operations](../docs/operations.md) for metrics.

## Troubleshooting

**`exec /usr/local/bin/curral: operation not permitted`, a port "already
allocated" with nothing using it, or DNS on `127.0.0.53` inside the
container.** This is the snap Docker (`which docker` → `/snap/bin/docker`).
Replace it with the official one:

```sh
docker ps -a; docker volume ls      # --purge deletes EVERYTHING in the snap Docker: back up first
docker compose down
sudo snap remove --purge docker
hash -r
curl -fsSL https://get.docker.com | sudo sh
docker compose up -d
```

**`Bind for 0.0.0.0:80 failed: port is already allocated` (with the official
Docker).** A proxy is already running on the host. Find it with
`sudo ss -ltnp | grep -E ':(80|443)\b'`. There are two ways out:
- Stop the existing proxy.
- Remove the `caddy` service, publish curral on the host only
  (`ports: ["127.0.0.1:8080:8080"]`) and point the existing proxy at
  `http://127.0.0.1:8080`. In that case, set `CURRAL_TRUSTED_PROXY` to the
  network gateway (`docker network inspect curral_curral`).

**`rego_parse_error: package expected` or invalid YAML.** There is garbage on
the first line, usually a ```` ``` ```` fence copied along. Check with
`head -2 config/*` and recreate the file with the heredoc.

**Caddy returns `502` with `lookup curral ... server misbehaving`.** curral
is not running. Check `docker compose logs curral`.

**Caddy gets no certificate.** The domain does not point to the server,
ports 80 and 443 are closed for inbound traffic, or the Cloudflare proxy is
on. Check `docker compose logs caddy`.

**External access error when reading a table.** `R2_ALLOWED_PATH` does not
cover the real path of the files. Check the "Filename(s)" field of an
`EXPLAIN ANALYZE` on the table.

**Permission denied reading `config/`.** Run the `chown 65532:65532` from
step 5.

## Security

- **Do not commit** `.env`, a `users.yaml` with real hashes, or passwords.
- **Exposed password** (pasted in a chat, a ticket or the shell history):
  generate a new one (step 4) and reload with `SIGHUP`.
- **R2 token:** give it the narrowest scope possible. With a read-only token,
  not even a permissive policy can write.
- **Metrics:** `/metrics` (`CURRAL_METRICS_LISTEN`) has no authentication. If
  you enable it, do not publish the port.
