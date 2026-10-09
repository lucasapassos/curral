# API HTTP do curral

Referência para agentes que só têm uma ferramenta HTTP. Para o fluxo de
trabalho, veja o `SKILL.md`.

## Conteúdo
- Autenticação
- `GET /v1/schema`
- `POST /v1/query`
- Dry run
- Headers e trailers
- Erros
- Outros endpoints

## Autenticação

Toda chamada (exceto `/healthz`) precisa do header `Authorization`:

| Header | Credencial |
|---|---|
| `Authorization: Basic base64(usuario:senha)` | usuário e senha |
| `Authorization: Bearer curral_...` | API key de serviço |
| `Authorization: Bearer eyJ...` | JWT de um provedor OIDC configurado no servidor |

Falhas repetidas de login bloqueiam o IP e o usuário por alguns minutos.
Nesse caso a resposta é 429 com `Retry-After`, mesmo com a senha certa.

## `GET /v1/schema`

Tabelas e views que **você** pode consultar, com colunas. Query string
opcional: `database`, `schema` e `table` (comparação sem diferenciar
maiúsculas).

```
GET /v1/schema?schema=analytics
```

```json
{
  "default_database": "lake",
  "databases": [
    {"name": "lake", "type": "iceberg", "schema": "analytics", "read_only": false}
  ],
  "tables": [
    {
      "database": "lake", "schema": "analytics", "name": "monthly_revenue", "kind": "table",
      "comment": "opcional",
      "row_filtered": true,
      "columns": [
        {"name": "region", "type": "VARCHAR", "nullable": true},
        {"name": "revenue", "type": "DOUBLE", "nullable": true, "masked": true}
      ]
    }
  ]
}
```

- **`databases[].schema`:** o schema usado para nomes não qualificados
  daquele database.
- **`kind`:** `table` ou `view`.
- **`masked` e `row_filtered`:** só aparecem quando valem `true`.
- **Atualização:** a listagem vem de cache. Uma tabela criada por outro
  sistema pode levar alguns minutos para aparecer.
- **404:** servidor antigo, sem o endpoint. Use `DESCRIBE` via `/v1/query`.

## `POST /v1/query`

Corpo JSON. Campos desconhecidos são rejeitados com 400.

```json
{
  "sql": "SELECT region, sum(revenue) AS total FROM monthly_revenue WHERE ref_date >= $1::DATE GROUP BY 1 ORDER BY 2 DESC",
  "params": ["2025-01-01"],
  "database": "lake",
  "format": "json",
  "max_rows": 100,
  "dry_run": false
}
```

| Campo | | |
|---|---|---|
| `sql` | obrigatório | um único comando |
| `params` | opcional | valores escalares (string, número, bool, null) para `$1`, `$2`... |
| `database` | opcional | database usado para nomes não qualificados; default `default_database` |
| `format` | opcional | `json` (padrão), `csv`, `ndjson`, `arrow`; também via `?format=` ou `Accept` |
| `max_rows` | opcional | no máximo N linhas nesta resposta; só reduz o limite do servidor/papel, nunca aumenta |
| `dry_run` | opcional | `true` = inspeciona e decide sem executar; a resposta traz o `max_rows` efetivo |

### Respostas por formato

**`json`:**

```json
{"columns":[{"name":"region","type":"VARCHAR"},{"name":"total","type":"DOUBLE"}],
 "data":[{"region":"A","total":123.4}],
 "row_count":1}
```

- **Tipos como string:** DECIMAL, HUGEINT e UUID vêm como string.
- **Erro no meio:** se a query falhou ou foi cortada no meio, o objeto
  termina com `"error": "..."`. Com corte pelo limite, é
  `"error": "row limit reached"`.

**`csv`:** cabeçalho na primeira linha, depois os dados. O status de
conclusão vem só nos trailers (abaixo).

**`ndjson`:** um objeto JSON por linha.

**`arrow`:** stream Arrow IPC (`application/vnd.apache.arrow.stream`), para
consumo por código.

## Dry run

```json
{"sql": "SELECT * FROM monthly_revenue", "dry_run": true}
```

```json
{"dry_run":true,"decision":"allow","decided_by":"policy","statement_type":"SELECT",
 "database":"lake","tables":["lake.analytics.monthly_revenue"],"targets":[],"functions":[],
 "databases":["lake"],"resolved":true,
 "limits":{"max_rows":10000,"timeout":"30s","max_concurrency":2},
 "row_filters":["lake.analytics.monthly_revenue"],
 "masked_columns":{"lake.analytics.monthly_revenue":["revenue"]},
 "policy_sha256":"..."}
```

- **`decision`:** `allow` ou `deny`.
- **`decided_by`:** quem decidiu. `policy` é a política de acesso. `engine`
  é uma regra fixa do servidor, como ATTACH, comandos múltiplos ou SQL
  inválido; nesse caso `reason` explica.
- **`resolved: false`:** o servidor não conseguiu determinar tudo que o
  comando lê. A política costuma negar esse caso.
- **SQL inválido:** responde 400, como uma query normal.

## Headers e trailers

| Nome | Onde | |
|---|---|---|
| `X-Request-Id` | header, toda resposta | identifica o request na auditoria |
| `X-Curral-Statement-Type` | header | `SELECT`, `EXPLAIN`, ... |
| `X-Curral-Max-Rows` | header | limite de linhas em vigor para este request |
| `X-Curral-Row-Count` | trailer | linhas enviadas |
| `X-Curral-Error` | trailer | erro depois do início do stream, incluindo `row limit reached` |

Trailers chegam **depois** do corpo. Muitos clientes HTTP não os expõem.
Nesse caso:
- em JSON, use o campo `error`;
- em CSV/NDJSON, compare o número de linhas com `X-Curral-Max-Rows`.

Uma conexão encerrada antes do fim do corpo é um resultado incompleto.

## Erros

Antes do stream começar, o erro vem como `{"error": "mensagem"}` com o status:

| Status | Causa |
|---|---|
| 400 | corpo inválido, SQL com erro de parser/binder/execução, múltiplos comandos, comando de transação |
| 401 | sem credencial ou credencial inválida (`WWW-Authenticate` indica os esquemas aceitos) |
| 403 | política negou, ou filtro/máscara não pôde ser garantido (ex.: leitura indireta por view) |
| 429 | limite de queries simultâneas do usuário, ou bloqueio por falhas de login; respeite `Retry-After` |
| 499 | cliente desconectou |
| 500 | falha ao avaliar a política |
| 503 | fila de execução cheia ou auditoria indisponível; respeite `Retry-After` |
| 504 | timeout da query |

## Outros endpoints

- `GET /v1/databases`: databases montados (nome, tipo, schema padrão,
  somente leitura).
- `GET /healthz`: sem autenticação; `{"status":"ok"}`.
