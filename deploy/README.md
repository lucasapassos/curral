# Instalação em servidor com Docker Compose

Sobe o curral num servidor remoto, servindo um **Cloudflare R2 Data Catalog**
(Iceberg), com HTTPS automático pelo Caddy (Let's Encrypt) e um usuário
`admin` sem restrições.

```
cliente ──HTTPS:443──▶ caddy ──HTTP:8080 (rede interna)──▶ curral ──▶ R2 Data Catalog
```

- **Caddy:** proxy reverso que obtém e renova o certificado TLS sozinho e
  repassa as requisições ao curral. Só ele publica portas (80 e 443).
- **curral:** não fica exposto na internet, só na rede interna do compose.

Neste guia, os valores entre `<...>` são seus. Nenhum deles deve ir para o
git.

## Pré-requisitos

- **Docker oficial**, instalado pelo repositório da Docker (`get.docker.com`).
  **Não use o Docker do snap**: o confinamento dele quebra o DNS dos
  containers e a publicação de portas, e bloqueia a execução do binário
  (`exec /usr/local/bin/curral: operation not permitted`). Veja
  [Problemas comuns](#problemas-comuns).
- **Um domínio** (ex.: `curral.example.com`) com registro A/AAAA apontando
  para o servidor. Se o DNS estiver no Cloudflare, deixe o proxy desligado
  (nuvem cinza) para o Let's Encrypt validar.
- **Portas 80 e 443** livres no host e abertas na entrada (firewall do
  provedor / security group).
- **No R2:** um bucket com Data Catalog habilitado e um API token com
  permissão de R2 Data Catalog e R2 Storage. Se o acesso deve ser só de
  leitura, use um token só de leitura.

```sh
which docker            # deve ser /usr/bin/docker, não /snap/bin/docker
```

## 1. Estrutura

```
~/curral/
├── .env                 # credenciais e domínio (chmod 600)
├── docker-compose.yml
├── Caddyfile
└── config/              # montado read-only em /etc/curral
    ├── catalog.yaml
    ├── users.yaml
    └── policy.rego
```

```sh
mkdir -p ~/curral/config && cd ~/curral
```

> Crie os arquivos com os heredocs abaixo (`cat > arquivo <<'EOF'`). Copiar o
> conteúdo de um bloco markdown para um editor costuma trazer junto a linha
> ```` ```yaml ````, o que quebra o parse (`rego_parse_error: package expected`).

## 2. `.env`

Os valores estão nas configurações do Data Catalog do bucket, no painel do R2.

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

| Variável | |
|---|---|
| `R2_CATALOG_URI` | "Catalog URI" do Data Catalog |
| `R2_WAREHOUSE` | "Warehouse name" do Data Catalog |
| `R2_TOKEN` | API token do Cloudflare |
| `R2_SCHEMA` | namespace Iceberg usado para nomes não qualificados |
| `R2_ALLOWED_PATH` | prefixo de storage das tabelas. Com o acesso externo desligado, é o único caminho remoto liberado |
| `R2_CACHE_TTL` | cache dos metadados do catálogo; commits de outros escritores podem levar esse tempo para aparecer |

## 3. Catálogo

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

Os `${...}` são expandidos pelo curral a partir das variáveis de ambiente do
container. O token não fica neste arquivo.

## 4. Usuário admin

Gere uma senha forte e o hash bcrypt dela:

```sh
openssl rand -base64 24                                        # guarde num gerenciador de senhas
docker run --rm -it lucasapassos/curral:v0.3.0 hash-password   # digite a senha; imprime o hash
```

```sh
cat > config/users.yaml <<'EOF'
users:
  - name: admin
    password_hash: "<hash bcrypt gerado acima>"
    roles: [admin]
EOF
```

O arquivo guarda só o hash, nunca a senha.

## 5. Política

O admin pode tudo:

```sh
cat > config/policy.rego <<'EOF'
package curral

import rego.v1

default allow := false

allow if "admin" in input.roles
EOF
```

**Somente leitura:** para o admin só ler, troque a regra por:

```rego
allow if {
	"admin" in input.roles
	input.statement_type in {"SELECT", "EXPLAIN"}
}
```

Como não são passados `--row-filters`, `--policy-masks-query` nem
`--policy-limits-query`, não há filtro de linhas, máscara de colunas nem
limite por role. Valem só os limites globais do compose. Para roles com
restrições, veja `examples/policy.rego` e `examples/roles.r2.json`.

**Permissões:** o container roda como o uid 65532, que precisa ler os
arquivos:

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

`{$CURRAL_DOMAIN}` vem do `.env`.

## 7. `docker-compose.yml`

```sh
cat > docker-compose.yml <<'EOF'
services:
  curral:
    image: lucasapassos/curral:v0.3.0
    environment:
      CURRAL_CATALOG: /etc/curral/catalog.yaml
      CURRAL_USERS: /etc/curral/users.yaml
      CURRAL_POLICY: /etc/curral/policy.rego
      CURRAL_ALLOWED_PATH: ${R2_ALLOWED_PATH:?}
      CURRAL_MAX_CONCURRENCY: 8
      CURRAL_MEMORY_LIMIT: 2GB
      CURRAL_QUERY_TIMEOUT: 600s
      CURRAL_AUDIT_LOG: /var/log/curral/audit.jsonl
      CURRAL_TRUSTED_PROXY: 172.31.247.10      # só o Caddy define X-Forwarded-For
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

- **IP fixo do Caddy:** `CURRAL_TRUSTED_PROXY` confia em `X-Forwarded-For`
  só vindo do IP do Caddy. Nunca use a sub-rede inteira, porque ela inclui o
  gateway do Docker.
- **Sub-rede:** se `172.31.247.0/24` colidir com uma rede local, troque a
  sub-rede e o IP do Caddy nos dois lugares.
- **Versão:** fixe a tag da imagem (`v0.3.0`) e atualize de propósito, não
  com `latest`.

## 8. Subir

```sh
docker compose up -d
docker compose ps                  # os dois "Up"; caddy com 0.0.0.0:80 e :443
docker compose logs -f caddy       # aguarde "certificate obtained successfully"
docker compose logs -f curral      # aguarde o ATTACH do lake e o listen em :8080
```

## 9. Testar

Da sua máquina:

```sh
curl -u admin https://<curral.example.com>/v1/query \
  -d '{"sql":"SELECT count(*) FROM <tabela>","format":"csv"}'
```

Com `-u admin` sem a senha, o curl pede a senha no terminal e ela não fica no
histórico do shell. Pelo cliente `curral`:

```sh
export CURRAL_URL=https://<curral.example.com> CURRAL_USER=admin
read -rs CURRAL_PASSWORD && export CURRAL_PASSWORD
curral query "SELECT * FROM <tabela> LIMIT 10"
```

## Operação

| Tarefa | Comando |
|---|---|
| Trocar senha / editar usuários ou política | edite `config/*` e `docker compose kill -s HUP curral` (sem restart) |
| Mudar o catálogo ou o `.env` | `docker compose up -d` (recria o container) |
| Atualizar a versão | troque a tag no compose e `docker compose up -d` |
| Auditoria | `docker compose exec` não funciona (imagem sem shell); leia o volume: `docker run --rm -v curral_audit:/a alpine tail /a/audit.jsonl` |
| Logs | `docker compose logs -f curral` |

Na auditoria, o SQL fica com os literais redigidos e as senhas nunca
aparecem.

## Problemas comuns

**`exec /usr/local/bin/curral: operation not permitted`, porta "already
allocated" sem nada usando, ou DNS em `127.0.0.53` dentro do container.**
É o Docker do snap (`which docker` → `/snap/bin/docker`). Troque pelo oficial:

```sh
docker ps -a; docker volume ls      # --purge apaga TUDO do Docker do snap: faça backup antes
docker compose down
sudo snap remove --purge docker
hash -r
curl -fsSL https://get.docker.com | sudo sh
docker compose up -d
```

**`Bind for 0.0.0.0:80 failed: port is already allocated` (com Docker
oficial).** Já há um proxy no host. Veja quem é com
`sudo ss -ltnp | grep -E ':(80|443)\b'`. Há duas saídas:
- Pare o proxy existente.
- Remova o serviço `caddy`, publique o curral só no host
  (`ports: ["127.0.0.1:8080:8080"]`) e aponte o proxy existente para
  `http://127.0.0.1:8080`. Nesse caso, ajuste `CURRAL_TRUSTED_PROXY` para o
  gateway da rede (`docker network inspect curral_curral`).

**`rego_parse_error: package expected` ou YAML inválido.** Há lixo na
primeira linha, normalmente uma cerca ```` ``` ```` copiada junto. Confira
com `head -2 config/*` e recrie o arquivo com o heredoc.

**Caddy com `502` e `lookup curral ... server misbehaving`.** O curral não
está rodando. Veja `docker compose logs curral`.

**Caddy sem certificado.** O domínio não aponta para o servidor, as portas
80 e 443 estão fechadas na entrada, ou o proxy do Cloudflare está ligado. Veja
`docker compose logs caddy`.

**Erro de acesso externo ao ler uma tabela.** O `R2_ALLOWED_PATH` não cobre o
caminho real dos arquivos. Confira o campo "Filename(s)" de um
`EXPLAIN ANALYZE` da tabela.

**Permissão negada ao ler `config/`.** Rode o `chown 65532:65532` do passo 5.

## Segurança

- **Não versione** o `.env`, o `users.yaml` com hashes reais, nem senhas.
- **Senha exposta** (colada em chat, ticket ou histórico de shell): gere uma
  nova (passo 4) e recarregue com `SIGHUP`.
- **Token do R2:** dê a ele o menor escopo possível. Com um token só de
  leitura, nem uma política permissiva consegue escrever.
- **Métricas:** o `/metrics` (`CURRAL_METRICS_LISTEN`) não tem autenticação.
  Se ativar, não publique a porta.
