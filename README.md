# curral

Servidor REST para executar queries DuckDB remotamente, com autenticação e
autorização (RBAC) via política Rego. É um único binário Go que embarca o
DuckDB: os databases declarados no catálogo são montados com `ATTACH` no
startup e as queries rodam num pool de conexões com concorrência limitada.

```
cliente ─HTTP─▶ curral
                 ├─ Basic auth (arquivo de usuários, bcrypt + cache)
                 ├─ fila (--max-concurrency, --queue-timeout)
                 ├─ PREPARE ─▶ tipo do statement, tabelas lidas/escritas, table functions
                 ├─ OPA embarcado (--policy *.rego) ─ allow?
                 └─ EXECUTE ─▶ CSV / JSON / NDJSON em streaming
```

## Instalação

Pelos [releases](https://github.com/lucasapassos/curral/releases), há duas opções:

```sh
# imagem multi-arch (linux/amd64, linux/arm64), pública no Docker Hub
docker pull lucasapassos/curral:latest

# binário (Linux, glibc 2.35+), com as extensões httpfs/avro/iceberg já instaladas
tar xzf curral_v0.1.0_linux_amd64.tar.gz && cd curral_v0.1.0_linux_amd64
./curral serve --extension-dir ./extensions --catalog ... --users ... --policy ...
```

A imagem é pública. Os binários ficam nos releases do GitHub, cujo acesso
segue a visibilidade do repositório.

**Publicar uma versão:** acrescente a seção `## [vX.Y.Z]` ao `CHANGELOG.md`
e envie a tag. O workflow `release` então:
1. roda os testes;
2. compila os binários das duas arquiteturas;
3. publica a imagem no Docker Hub (precisa do secret `DOCKERHUB_TOKEN`);
4. cria o release com as notas da seção.

```sh
git tag v0.2.0 && git push origin v0.2.0
```

## Cliente

```sh
export CURRAL_URL=https://curral.example.com CURRAL_TOKEN=curral_...   # ou CURRAL_USER/CURRAL_PASSWORD
curral query "SELECT * FROM orders LIMIT 10"                          # CSV no stdout
curral query -f arrow -o orders.arrow "SELECT * FROM orders"
curral query -p 42 "SELECT * FROM orders WHERE id = \$1"
echo "DELETE FROM orders" | curral query --dry-run -f json
```

O `curral query` sai com código de erro em respostas de erro e quando o
resultado chega incompleto. Para Python, veja `clients/python`.

## Build

Requer Go 1.25+ e um compilador C (cgo, por causa do DuckDB).

```sh
go build -tags duckdb_arrow -ldflags "-s -w" -o bin/curral ./cmd/curral
go test -tags duckdb_arrow ./...
```

A tag `duckdb_arrow` habilita a saída Arrow IPC e é usada na imagem Docker e no
CI. Sem ela o build funciona igual, mas `format: arrow` responde 400.

## Docker

```sh
docker compose up --build        # usa .env (credenciais do R2) e examples/
```

- **Imagem `distroless/cc`** (~190 MB), com usuário não-root e sem shell.
- **Extensões `httpfs`, `avro` e `iceberg`** são instaladas no build com o próprio DuckDB do binário, então o container sobe **sem acesso à internet** e com versões fixas. Outras extensões: `--build-arg EXTENSIONS="httpfs avro iceberg postgres"`.
- **O `docker-compose.yml`** roda com filesystem somente leitura, `cap_drop: ALL` e tmpfs para o spill do DuckDB, e publica a porta só em `127.0.0.1`. Ele exige `R2_SCHEMA` e `R2_ALLOWED_PATH`, e aceita as credenciais como `R2_*` ou `LAKE_*`.
- **Subcomandos de apoio:** `curral version`, `curral healthcheck [url]` (usado no `HEALTHCHECK`, já que não há curl na imagem) e `curral install-extensions --extension-dir DIR nomes...`.

## Uso

```sh
curral hash-password                       # gera o bcrypt para users.yaml

CURRAL_DATA=./data curral serve \
  --catalog examples/catalog.yaml \
  --users   examples/users.yaml \
  --policy  examples/policy.rego \
  --policy  examples/roles.json \
  --max-concurrency 8 --queue-timeout 5s --query-timeout 60s \
  --memory-limit 8GB --threads 8

curral check ...                           # valida os arquivos e monta o catálogo sem subir o HTTP
curral serve -h                            # todos os flags
```

Todo flag também pode vir do ambiente como `CURRAL_<FLAG>`, por exemplo
`CURRAL_MAX_CONCURRENCY=16`. Flags repetíveis aceitam uma lista separada por
vírgula: `CURRAL_POLICY=policy.rego,roles.json`.

| Flag | Default | |
|---|---|---|
| `--catalog` | — | extensões, secrets e databases (`ATTACH`) |
| `--users` | — | usuários, hash bcrypt e roles |
| `--policy` | — | `.rego` ou dados JSON/YAML (`data.*`), repetível |
| `--policy-query` | `data.curral.allow` | decisão que precisa ser `true` |
| `--policy-limits-query` | (desligado) | regra opcional com limites por request, ex.: `data.curral.limits` |
| `--max-concurrency` | 8 | queries executando ao mesmo tempo |
| `--queue-timeout` | 5s | espera por um slot livre; depois disso responde 503 |
| `--max-concurrency-per-user` | 0 (sem limite) | queries simultâneas por usuário quando a política não define `max_concurrency` |
| `--query-timeout` | 60s | duração máxima; depois disso responde 504 |
| `--max-rows` | 0 | limite de linhas por resposta (0 = sem limite) |
| `--threads`, `--memory-limit`, `--temp-dir`, `--max-temp-size` | | recursos do DuckDB |
| `--extension-dir` | | extensões pré-instaladas (offline) |
| `--external-access` | false | mantém `enable_external_access` ligado |
| `--allowed-path` | | prefixo (diretório ou `s3://bucket/`) liberado com acesso externo desligado, repetível |
| `--auth-cache-ttl` | 5m | cache de senhas já verificadas |
| `--oidc-issuer` / `--oidc-audience` | (desligado) | aceita JWTs desse provedor OIDC; a audience é obrigatória |
| `--oidc-user-claim` / `--oidc-roles-claim` | `sub` / `roles` | claims de usuário e roles (aceita caminho com ponto: `realm_access.roles`) |
| `--oidc-skew` | 30s | tolerância de relógio para `exp`/`nbf` |
| `--oidc-require-email-verified` | true | com `--oidc-user-claim email`, exige `email_verified=true` |
| `--oidc-hosted-domain` | (qualquer) | aceita só tokens com essa claim `hd` (domínio Google Workspace), repetível |
| `--audit-log` | (desligado) | arquivo JSONL de auditoria; `-` = stdout; `SIGHUP` reabre |
| `--audit-sql` | `redacted` | texto do SQL na auditoria: `redacted`, `full` ou `hash` |
| `--audit-queue` | 4096 | eventos em memória aguardando escrita |
| `--metrics-listen` | (desligado) | endereço separado para o `/metrics` do Prometheus, ex.: `127.0.0.1:9090` |
| `--tls-cert` / `--tls-key` | (HTTP puro) | HTTPS nativo, TLS 1.2+; o certificado recarrega no `SIGHUP` |
| `--trusted-proxy` | (nenhum) | IP/CIDR de proxy que pode definir `X-Forwarded-For`, repetível |
| `--auth-ip-max-failures` | 10 | falhas de login por IP na janela antes do bloqueio (0 = off) |
| `--auth-user-max-failures` | 30 | falhas por nome de usuário na janela antes do bloqueio (0 = off) |
| `--auth-failure-window` / `--auth-lockout` | 5m / 15m | janela de contagem / duração do bloqueio |

## Catálogo

Ver `examples/catalog.yaml`. Os valores aceitam `${VAR}` e `${VAR:-default}`.
Uma variável ausente sem default aborta o boot, para que credenciais nunca
fiquem vazias por engano. As opções do `ATTACH` e dos secrets são repassadas
como estão, então Iceberg, Postgres, S3 etc. funcionam do mesmo jeito:

```yaml
extensions: [httpfs, iceberg]
secrets:
  - name: lake_catalog
    type: iceberg
    params: { CLIENT_ID: "${ICEBERG_CLIENT_ID}", CLIENT_SECRET: "${ICEBERG_CLIENT_SECRET}" }
databases:
  - name: lake
    path: ${ICEBERG_WAREHOUSE}
    options: { TYPE: iceberg, SECRET: lake_catalog, ENDPOINT: "${ICEBERG_ENDPOINT}" }
```

Os valores de secrets e os paths aparecem redigidos no log.

O campo `schema` (default `main`) define o schema usado para nomes não
qualificados. Catálogos Iceberg não têm `main`, então informe o namespace
(ex.: `schema: analytics`).

### Cloudflare R2 Data Catalog

O exemplo está em `examples/catalog.r2.yaml` e `examples/r2.env.example`. Não é
preciso secret S3, porque o R2 entrega as credenciais de storage pelo catálogo.
Com o acesso externo desligado, libere só o bucket:

```sh
curral serve --catalog examples/catalog.r2.yaml ... --allowed-path s3://<bucket>/
```

#### Cache de metadados do catálogo (`cache_ttl`)

A cada request o DuckDB pede ao catálogo REST os metadados da tabela
(`loadTable`), e não há cache disso entre transações. No R2 essa ida custa
250–900 ms, quase todo o tempo da query. Os arquivos (avro, parquet) já ficam
no cache de arquivos externos do próprio DuckDB.

`cache_ttl` coloca um proxy de cache local (`127.0.0.1`) entre o DuckDB e o
catálogo:

```yaml
databases:
  - name: lake
    path: ${R2_WAREHOUSE}
    schema: analytics
    cache_ttl: 30s
    options: { TYPE: iceberg, SECRET: r2_catalog, ENDPOINT: "${R2_CATALOG_URI}" }
```

- **Regras de cache:**
  - Só respostas 200 a GET entram no cache.
  - A chave inclui o hash do `Authorization`.
  - Requisições simultâneas iguais viram uma só ida ao upstream.
- **Escritas:** qualquer POST/PUT/DELETE (commit) passa direto e esvazia o cache.
- **Credenciais temporárias:** se a resposta trouxer `*expires-at-ms`, a entrada expira 1 minuto antes das credenciais. O R2 não informa expiração, então mantenha o TTL curto.
- **Trade-off:** commits de **outros** escritores podem levar até `cache_ttl` para aparecer.

Medido contra o R2 (agregação simples, via HTTP com auth e política):

| | sem cache | `cache_ttl: 30s` |
|---|---|---|
| p50, 1 cliente | 273 ms | 8 ms |
| throughput, 8 clientes | 3 req/s | 338 req/s |

Teste de integração (pulado sem as variáveis):

```sh
source .env.r2 && go test ./internal/engine -run R2 -v
```

## API

`POST /v1/query` com `Authorization: Basic ...`:

```json
{"sql": "SELECT * FROM orders WHERE id = $1", "params": [42], "database": "sales", "format": "csv"}
```

- **`format`**: `csv`, `json` (default), `ndjson` ou `arrow` (Arrow IPC stream,
  `application/vnd.apache.arrow.stream`). Também pode vir de `?format=` ou do header `Accept`.
- **`database`**: catálogo usado para nomes não qualificados. O default vem do campo `default` do catálogo.
- **Resposta em JSON**: `{"columns":[{"name","type"}],"data":[{...}],"row_count":N}`.
- **Tipos convertidos para string**: DECIMAL, HUGEINT e UUID, para não perder precisão.
- **Erro no meio do stream**: com o status 200 já enviado, o erro vai no trailer `X-Curral-Error`. No JSON ele também aparece como campo `"error"`. O trailer `X-Curral-Row-Count` traz o total de linhas.
- **Erros antes do stream**: `{"error": "..."}` com 400 (SQL inválido), 401, 403, 499 (cliente desconectou), 503 (fila cheia) ou 504 (timeout).

Outros endpoints: `GET /v1/databases` (autenticado) e `GET /healthz`.

## Autenticação

Três métodos, escolhidos pelo header `Authorization`:

| Header | Método | Origem das roles |
|---|---|---|
| `Basic base64(user:senha)` | usuário local (bcrypt, com cache) | `users[].roles` no arquivo de usuários |
| `Bearer curral_...` | API key de serviço | `api_keys[].roles` no arquivo de usuários |
| `Bearer <JWT>` | token OIDC (Keycloak, Auth0, Entra, Google...) | claim `--oidc-roles-claim` |

- **API keys**: `curral gen-api-key etl-job etl` mostra a chave **uma vez** e a
  entrada para o arquivo. O arquivo guarda só o SHA-256 da chave. `expires` é
  opcional. Como usuários, as API keys recarregam com `SIGHUP`.
- **JWT**:
  - **Boot:** o curral faz a descoberta OIDC e baixa o JWKS. Se o provedor estiver inacessível, o boot falha.
  - **Chaves:** o JWKS é atualizado em segundo plano.
  - **Validação:** assinatura, `iss`, `aud`, `exp` e `nbf`. Tokens sem assinatura (`alg: none`) ou de outra chave são recusados.
  - **Roles:** a claim pode ser uma lista ou uma string separada por espaços (ex.: `scope`).
- **Rastreio:** a auditoria registra `auth_method` (`basic`, `api_key`, `jwt`). `curral_auth_failures_total{method}` separa as falhas por método, e o log operacional traz o motivo. O cliente recebe sempre só 401.

```sh
curral serve ... --oidc-issuer https://sso.example.com/realms/main --oidc-audience curral \
  --oidc-user-claim preferred_username --oidc-roles-claim realm_access.roles
```

### Roles por identidade (`identities:`)

Alguns provedores não mandam roles no token (o Google, por exemplo). A seção
`identities` do arquivo de usuários atribui roles por usuário ou por domínio
de e-mail, e recarrega com `SIGHUP`:

```yaml
identities:
  - match: ana@gmail.com      # exato, sem diferenciar maiúsculas
    roles: [analyst]
  - match: "*@example.com"    # qualquer endereço do domínio (não pega subdomínios)
    roles: [analyst]
```

As roles mapeadas se somam às que o token já trouxer. Um usuário autenticado
que não aparece em nenhuma entrada (nem tem roles no token) não recebe acesso a
nada da política de exemplo.

### Google

```sh
curral serve ... \
  --oidc-issuer https://accounts.google.com \
  --oidc-audience <CLIENT_ID>.apps.googleusercontent.com \
  --oidc-user-claim email
  # opcional, contas Google Workspace: --oidc-hosted-domain example.com
```

- **Client ID:** crie um OAuth Client em Google Cloud Console → APIs &
  Services → Credentials.
- **Token:** o cliente envia o **ID token** (JWT) em
  `Authorization: Bearer ...`. Access tokens do Google não são JWT e não servem.
- **Quem consegue logar:** com a tela de consentimento "External", qualquer
  conta Google obtém um token válido para o seu client ID. O acesso vem só de
  `identities`, e `email_verified` é exigido para que uma conta com e-mail não
  verificado não se passe por um endereço mapeado.
- **Teste local:** `gcloud auth print-identity-token` gera um ID token cuja
  audience é o client ID do próprio gcloud. Não use essa audience em produção:
  qualquer usuário do gcloud teria tokens aceitos.

## Exposição na rede: TLS e força bruta

**TLS.** Sem TLS, senhas, API keys e tokens trafegam em claro, e o curral
avisa isso no boot. Há duas opções:
- **TLS nativo:** `--tls-cert`/`--tls-key`. O `SIGHUP` recarrega o certificado
  sem derrubar conexões, e um arquivo inválido mantém o certificado atual.
- **Proxy com certificado automático:** `docker compose --profile tls up`
  sobe um Caddy na frente, com Let's Encrypt para `CURRAL_DOMAIN` ou CA local
  para `localhost`, e HSTS.

**Força bruta.**
- **Contagem:** falhas de autenticação são contadas por IP e por nome de
  usuário. O limite por usuário pega ataques distribuídos.
- **Bloqueio:** passado o limite, o request recebe **429** com `Retry-After`,
  **mesmo com a credencial certa**. O bloqueio é checado antes do bcrypt, então
  não gasta CPU.
- **CPU:** o bcrypt roda com concorrência limitada ao número de CPUs, para que
  uma enxurrada de senhas erradas não esgote a máquina.
- **Rastreio:** eventos `auth_blocked` na auditoria e as métricas
  `curral_auth_lockouts_total{scope}` e `curral_auth_blocked_total{scope}`.
- **Trade-off:** o bloqueio por usuário permite que alguém bloqueie
  temporariamente uma conta alheia errando a senha dela. Ajuste
  `--auth-user-max-failures`, ou use 0 para desligar.

**IP real atrás de proxy.** O curral só usa `X-Forwarded-For` quando a conexão
vem de um `--trusted-proxy`, e lê da direita para a esquerda, parando no
primeiro IP não confiável. Assim, um IP que o próprio cliente escreve no header
nunca é aceito. Confie **só no IP do proxy**, nunca na sub-rede Docker
inteira: ela inclui o gateway, por onde chega qualquer acesso às portas
publicadas no host, que poderiam então forjar o header. O compose fixa o IP do
Caddy (`CURRAL_PROXY_IP`) por esse motivo.

## Auditoria

Com `--audit-log`, cada request gera uma linha JSON num arquivo próprio,
separado do log operacional. Falhas de autenticação e negações também geram
evento.

```json
{"ts":"...","event":"query","request_id":"1a1147f8f9b0...","user":"analyst","roles":["analyst"],
 "remote_addr":"10.0.0.7","database":"sales","statement_type":"SELECT",
 "sql":"SELECT count(*) FROM orders WHERE amount > ?","sql_sha256":"...","params_count":0,
 "tables":["sales.main.orders"],"resolved":true,"decision":"allow","decided_by":"policy",
 "policy_sha256":"...","status":200,"rows":1,"bytes":42,
 "timing_ms":{"queue":0,"inspect":1.2,"authorize":0.25,"execute":1.7,"total":3.3},
 "curral_version":"0.2.0"}
```

- **`decision`** pode ser `allow`, `deny` ou `error`. **`decided_by`** indica quem decidiu: `policy`, `engine` (ATTACH, multi-statement, SQL inválido), `auth`, `queue`, `audit` ou `request`.
- **`policy_sha256`** é o hash dos arquivos de política, para provar qual versão da regra decidiu.
- **`request_id`** também volta no header `X-Request-Id` e aparece no log operacional.
- **SQL:** por padrão, literais viram `?`, porque podem conter dados pessoais. Se o SQL usar construções que o tokenizer não lê com segurança, fica só o `sql_sha256`. Os valores de `params` nunca são registrados, só a contagem. Senhas nunca aparecem.
- **Fail-closed:** antes de executar, o curral reserva espaço na fila de auditoria. Se o arquivo não puder ser escrito (disco cheio, permissão) ou a fila estiver cheia, a query responde **503** e não executa. A recuperação é verificada a cada 5 s gravando um evento `audit_recovered`.
- **Rotação:** mova o arquivo e envie `SIGHUP` (`copytruncate` não é necessário). O arquivo novo começa com um evento `audit_reopened`.
- **Custo:** imperceptível nas medições (escrita assíncrona em lote).

Limitação: um crash do processo entre o commit de uma escrita e a gravação do
evento pode perder esse evento. A reserva prévia cobre disco cheio e falhas
de permissão, mas não queda do processo.

## Métricas

Com `--metrics-listen`, o `/metrics` (formato Prometheus) é servido numa porta
separada da API e **sem autenticação**. Mantenha essa porta na rede interna.

| Métrica | Tipo | Labels |
|---|---|---|
| `curral_queries_total` | counter | `status`, `decision`, `decided_by`, `statement_type` |
| `curral_policy_decisions_total` | counter | `role`, `decision` (cada role do usuário conta uma vez) |
| `curral_query_stage_seconds` | histogram | `stage`: `queue`, `inspect`, `authorize`, `execute`, `total` |
| `curral_queries_running` / `curral_queries_waiting` / `curral_query_slots` | gauge | |
| `curral_rows_returned_total` / `curral_response_bytes_total` | counter | |
| `curral_auth_failures_total` | counter | |
| `curral_audit_events_written_total` / `curral_audit_events_dropped_total` | counter | |
| `curral_audit_healthy` | gauge | 0 = queries sendo recusadas |
| `curral_catalog_cache_requests_total` | counter | `database`, `result` (`hit`, `miss`) |
| `curral_build_info` | gauge | `version`, `commit`, `duckdb`, `policy_sha256` |

Também saem as métricas padrão do runtime Go e do processo (`go_*`, `process_*`).

Alertas sugeridos:
- `curral_audit_healthy == 0`: as queries estão sendo recusadas.
- `rate(curral_queries_total{status="503"}[5m]) > 0`: fila cheia ou auditoria fora.
- `curral_queries_waiting > 0` por muito tempo: aumentar `--max-concurrency`.
- Um pico em `curral_policy_decisions_total{decision="deny"}` ou em `curral_auth_failures_total`.

## Reload sem restart

`SIGHUP` (ou `docker compose kill -s HUP curral`) recarrega o **arquivo de
usuários** e a **política** (`.rego` e dados) e reabre o log de auditoria.

- **Arquivo novo inválido:** a versão anterior continua valendo e o erro vai para o log.
- **Troca atômica:** requests em andamento terminam com a versão com que começaram.
- **Cache de senhas:** é descartado, então usuários removidos ou com senha trocada perdem acesso na hora.
- **Rastreio:** cada tentativa gera um evento `config_reload` na auditoria, com o `policy_sha256` novo ou o erro, e conta em `curral_config_reloads_total`. `curral_policy_info` mostra o hash em vigor.
- **Catálogo:** é montado e travado no boot, então mudanças nele exigem restart.

## Dry-run

`"dry_run": true` no `/v1/query` faz a inspeção e avalia a política **sem
executar**. É útil para escrever e depurar `.rego`:

```sh
curl -u analyst:analyst-pw -d '{"sql":"DELETE FROM orders WHERE id = 1","dry_run":true}' localhost:8080/v1/query
```
```json
{"dry_run":true,"decision":"deny","decided_by":"policy","statement_type":"DELETE",
 "database":"sales","tables":["sales.main.orders"],"targets":["sales.main.orders"],
 "functions":[],"databases":["sales"],"resolved":true,"policy_sha256":"..."}
```

- **Negações do engine** (ATTACH, `UPDATE EXTENSIONS`...) aparecem como `"decided_by":"engine"`.
- **SQL inválido** continua respondendo 400.
- **Escopo:** o dry-run avalia a política para o próprio usuário autenticado. Ele vai para a auditoria como evento `dry_run`, mas fica fora das métricas de queries.

## Limites por role

Com `--policy-limits-query data.curral.limits`, depois que a política permite
o request, essa regra pode devolver limites para ele:

```rego
limits := {"timeout": "30s", "max_rows": 10000} if "analyst" in input.roles
```

- **`timeout`:** aceita string de duração ou segundos e vale para a execução.
- **`max_rows`:** corta a resposta, com o trailer `X-Curral-Error: row limit reached`.
- **Teto global:** `--query-timeout` e `--max-rows` continuam valendo, e prevalece sempre o mais restritivo.
- **Sem limites:** resultado indefinido significa nenhum limite.
- **Fail-closed:** se a regra falhar (formato inválido, conflito de valores), o request é negado com 500.
- **Onde aparecem:** na resposta do dry-run e no evento de auditoria (`limits`).
- **Exemplo pronto:** `examples/policy.rego` lê os limites de `data.roles[role].limits`. No exemplo, o analyst tem 30 s, 10 mil linhas e 2 queries simultâneas.

## Desempenho

Medido no caminho HTTP completo (auth, inspeção, política, execução e
serialização), numa máquina de 6 cores:

| Cenário | Tempo |
|---|---|
| `SELECT 1` / point lookup | ~0,7 ms / ~0,9 ms por request |
| 1 milhão de linhas (4 colunas), CSV | ~570 ms |
| 1 milhão de linhas, JSON | ~580 ms |
| 1 milhão de linhas, **Arrow** | **~140 ms** |
| Iceberg no R2 com `cache_ttl` | ~8 ms (sem cache: 250–900 ms) |

- **Resultados grandes: prefira `format: arrow`.** O DuckDB converte vetores
  inteiros direto para Arrow, sem converter valor por valor. Clientes como
  pyarrow, polars e o próprio DuckDB leem o stream direto.
- **CSV e JSON:** os formatadores de decimal, data e CSV são escritos à mão e
  testados contra as implementações de referência do Go e do driver.
- **Queries pequenas:** a latência é dominada pelo custo fixo do DuckDB. Cerca
  de 0,25 ms vêm de garantias que foram mantidas de propósito: conexão nova por
  request (isolamento entre usuários) e a inspeção que alimenta a política.

## Justiça entre usuários

`--max-concurrency` é o total de queries simultâneas da instância. Para um
usuário não ocupar todos os slots, há duas formas de definir uma cota por
usuário:
- **Na política**, com `max_concurrency` na regra de limites.
- **Como padrão**, com `--max-concurrency-per-user`, que vale quando a política
  não define nada.

```rego
limits := {"max_concurrency": 2} if "analyst" in input.roles                   # por usuário
limits := {"max_concurrency": 4, "concurrency_group": "role:etl"} if "etl" in input.roles  # cota da role
```

- **Por padrão a cota é individual.** Com `concurrency_group`, todos os
  usuários do grupo dividem a mesma cota.
- **Quem passa da cota recebe 429 na hora** (`Retry-After: 1`), em vez de
  esperar na fila. Esperar ocuparia um slot global e uma transação, que é
  justamente o que se quer evitar.
- **Rastreio:** a recusa vai para a auditoria (`decided_by: concurrency`) e
  conta em `curral_queries_throttled_total`.
- **Dry-run:** mostra a cota, mas não a consome.

Medição com `--max-concurrency 4`, um usuário disparando 12 queries pesadas e
outro fazendo uma query simples:

| | usuário comum | usuário abusivo |
|---|---|---|
| sem cota | esperou 5 s e recebeu **503** | 8 executaram, 4 receberam 503 |
| `--max-concurrency-per-user 2` | **200 em 2 ms** | 2 executaram, 10 receberam 429 |

## Política (input)

```json
{
  "user": "analyst", "roles": ["analyst"], "sql": "...",
  "statement_type": "SELECT",
  "database": "sales",
  "tables":    ["sales.main.orders"],
  "targets":   [],
  "functions": ["range"],
  "databases": ["sales"],
  "resolved":  true
}
```

- **`tables`**: tabelas base lidas, com views expandidas. Vêm do plano lógico **não otimizado** do próprio DuckDB, então JOIN/USING, CTEs, subqueries e views não escapam.
- **`targets`**: objetos escritos, criados ou removidos. O DuckDB não expõe isso, então eles vêm de um tokenizer.
  - Quando não dá para determinar o alvo, `resolved` é `false` e a política deve negar.
  - Formatos: `secret:<nome>` para secrets e `db.schema.*` para schemas.
- **`functions`**: table functions usadas como fonte (`read_parquet`, `range`, ...). Elas não passam por grants de tabela, então a política precisa liberá-las explicitamente.
- **`EXPLAIN ANALYZE <stmt>`**: é autorizado como `<stmt>`, porque executa o statement.
- **Catálogos externos (Iceberg etc.)**: o plano do DuckDB não traz o nome da tabela nesses scans. Para SELECT, as tabelas vêm da AST do parser (`json_serialize_sql`), respeitando o escopo dos CTEs. Qualquer outro statement que leia esses catálogos (ex.: `INSERT ... SELECT`, `CREATE TABLE AS`) chega com `resolved=false`.

`examples/policy.rego` traz um modelo com `admin` (tudo), `analyst` (leitura
por database, com tabelas negadas) e `etl` (DML em databases graváveis).

## Segurança

Proteções que valem independentemente da política:

- **`lock_configuration`**: depois do boot a configuração fica travada e os clientes não conseguem mudar settings.
- **Acesso externo**: `enable_external_access=false` por padrão. `read_*`, `COPY ... TO` e `ATTACH` novos ficam bloqueados.
- **Extensões**: autoinstall/autoload e extensões community ficam desligados.
- **Statements sempre negados**: `ATTACH`, `DETACH`, `LOAD`, `INSTALL` e `UPDATE EXTENSIONS`, qualquer que seja a política.
- **Inspeção fail-closed**:
  - Statements com construções léxicas que o tokenizer não modela igual ao DuckDB (`$$...$$`, comentários aninhados, `E'...'`) ficam com `resolved=false`.
  - O verbo encontrado pelo tokenizer precisa bater com o tipo que o DuckDB preparou.
  - Tipos sem tratamento explícito (CALL, VACUUM, COPY DATABASE...) também ficam com `resolved=false`.
- **Ambiente limpo**: as variáveis referenciadas no catálogo (`${R2_TOKEN}`...) são removidas do ambiente do processo depois do boot.
- **Multi-statement**: rejeitado antes de executar qualquer coisa.
- **Conexão nova por request**: tabelas TEMP, variáveis e `USE` não vazam entre usuários.
- **Uma transação por request**: inspeção, autorização e execução veem o mesmo snapshot. Os metadados de catálogos remotos são buscados uma vez por request; falhas fazem rollback.

## Verificação da inspeção

O RBAC depende de a inspeção reportar corretamente o que um statement escreve.
Isso é verificado contra o comportamento real do DuckDB por um **fuzz
diferencial** (`internal/engine/fuzz_test.go`):
1. Executa cada statement gerado.
2. Compara um retrato de todos os catálogos (linhas, colunas, tabelas, views, schemas, sequences e macros) antes e depois.
3. Falha se algum objeto alterado não estiver nos `targets` de uma inspeção marcada como `resolved`.

```sh
go test ./internal/engine -run '^$' -fuzz FuzzWriteTargets -fuzztime 5m         # mutação livre
go test ./internal/engine -run '^$' -fuzz FuzzWriteTargetsGrammar -fuzztime 5m  # gramática de DML/DDL
```

- **No CI normal** rodam o corpus de seeds e uma varredura exaustiva (templates × grafias de nomes).
- **Toda semana** o workflow `fuzz` roda os dois fuzzers por 10 minutos cada.
- **Achados desse processo**, todos já corrigidos e cobertos por testes de regressão:
  - bypass com `$$...$$`;
  - `ALTER ... RENAME TO` sem o nome novo nos alvos;
  - `memory.t` resolvido no catálogo errado;
  - nomes de objetos com UTF-8 inválido quebrando os metadados do DuckDB.

## Limitações conhecidas

- **Resultado materializado**: o driver Go materializa o resultado inteiro no DuckDB antes de entregar a primeira linha. Use `--memory-limit`/`--temp-dir` e, se precisar, `--max-rows`.
- **Bind antes da autorização**: a inspeção faz bind da query antes da política, então um `read_csv` remoto pode ser "farejado" no bind. Com acesso externo desligado (o padrão), isso é bloqueado pelo DuckDB.
- **Bind antes da autorização em fontes remotas**: o bind de `iceberg_scan('s3://...')` lê metadados (dentro de `--allowed-path`) antes da política. Dados não são devolvidos, mas a mensagem de erro pode revelar a existência ou o schema de uma tabela.
- **Latência do Iceberg sem `cache_ttl`**: cada request vai ao catálogo REST (~0,3–1 s no R2), e as chamadas simultâneas não ganham com paralelismo.
- **Formatos de nome nos alvos de escrita**: nomes de duas partes (`x.t`) são resolvidos como `database.main.t` quando `x` é um database do catálogo, e como `schema.t` do database corrente caso contrário.
