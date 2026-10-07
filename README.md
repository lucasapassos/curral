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

## Build

Requer Go 1.25+ e um compilador C (cgo, por causa do DuckDB).

```sh
go build -ldflags "-s -w" -o bin/curral ./cmd/curral
go test ./...
```

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
| `--max-concurrency` | 8 | queries executando ao mesmo tempo |
| `--queue-timeout` | 5s | espera por um slot livre; depois disso responde 503 |
| `--query-timeout` | 60s | duração máxima; depois disso responde 504 |
| `--max-rows` | 0 | limite de linhas por resposta (0 = sem limite) |
| `--threads`, `--memory-limit`, `--temp-dir`, `--max-temp-size` | | recursos do DuckDB |
| `--extension-dir` | | extensões pré-instaladas (offline) |
| `--external-access` | false | mantém `enable_external_access` ligado |
| `--allowed-path` | | prefixo (diretório ou `s3://bucket/`) liberado com acesso externo desligado, repetível |
| `--auth-cache-ttl` | 5m | cache de senhas já verificadas |

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

- **`format`**: `csv`, `json` (default) ou `ndjson`. Também pode vir de `?format=` ou do header `Accept`.
- **`database`**: catálogo usado para nomes não qualificados. O default vem do campo `default` do catálogo.
- **Resposta em JSON**: `{"columns":[{"name","type"}],"data":[{...}],"row_count":N}`.
- **Tipos convertidos para string**: DECIMAL, HUGEINT e UUID, para não perder precisão.
- **Erro no meio do stream**: com o status 200 já enviado, o erro vai no trailer `X-Curral-Error`. No JSON ele também aparece como campo `"error"`. O trailer `X-Curral-Row-Count` traz o total de linhas.
- **Erros antes do stream**: `{"error": "..."}` com 400 (SQL inválido), 401, 403, 499 (cliente desconectou), 503 (fila cheia) ou 504 (timeout).

Outros endpoints: `GET /v1/databases` (autenticado) e `GET /healthz`.

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

## Limitações conhecidas

- **Resultado materializado**: o driver Go materializa o resultado inteiro no DuckDB antes de entregar a primeira linha. Use `--memory-limit`/`--temp-dir` e, se precisar, `--max-rows`.
- **Bind antes da autorização**: a inspeção faz bind da query antes da política, então um `read_csv` remoto pode ser "farejado" no bind. Com acesso externo desligado (o padrão), isso é bloqueado pelo DuckDB.
- **Bind antes da autorização em fontes remotas**: o bind de `iceberg_scan('s3://...')` lê metadados (dentro de `--allowed-path`) antes da política. Dados não são devolvidos, mas a mensagem de erro pode revelar a existência ou o schema de uma tabela.
- **Latência do Iceberg sem `cache_ttl`**: cada request vai ao catálogo REST (~0,3–1 s no R2), e as chamadas simultâneas não ganham com paralelismo.
- **Formatos de nome nos alvos de escrita**: nomes de duas partes (`x.t`) são resolvidos como `database.main.t` quando `x` é um database do catálogo, e como `schema.t` do database corrente caso contrário.
