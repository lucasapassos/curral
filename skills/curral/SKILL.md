---
name: curral
description: Consulta dados por um servidor curral (API REST que executa SQL DuckDB sobre bancos DuckDB e catálogos Iceberg, como o Cloudflare R2 Data Catalog, com autenticação e permissões por usuário). Use esta skill sempre que for ler dados através do curral, por exemplo quando houver CURRAL_URL/CURRAL_TOKEN no ambiente, quando o usuário mencionar o curral, o "lake" ou tabelas servidas por ele, ou pedir números, relatórios, exportações ou a estrutura das tabelas que vivem lá, mesmo sem citar o nome curral. Cobre a descoberta do schema (/v1/schema), a escrita do SQL, a validação com dry_run, os limites de linhas e a interpretação de erros 400/401/403/429/503/504.
---

# Consultar dados pelo curral

O curral é um servidor HTTP na frente de um DuckDB. Você envia **um** comando
SQL por request para `POST /v1/query` e recebe o resultado em JSON, CSV,
NDJSON ou Arrow. Cada request passa por uma política de acesso que decide,
por usuário:
- quais tabelas ele pode ler;
- quais linhas ele vê (filtro de linhas);
- quais colunas chegam mascaradas;
- quantas linhas e quanto tempo cada query pode usar.

Você opera como um usuário comum desse servidor. As restrições são
intencionais: o objetivo é responder bem **dentro** delas e dizer ao usuário
o que elas impediram.

## Conexão

As credenciais ficam no ambiente, nunca no texto da resposta nem em arquivos:

| Variável | Uso |
|---|---|
| `CURRAL_URL` | ex.: `https://curral.example.com` |
| `CURRAL_TOKEN` | API key (`curral_...`) ou JWT, enviado como `Authorization: Bearer ...` |
| `CURRAL_USER` + `CURRAL_PASSWORD` | Basic auth, usado se não houver token |

Se o usuário passar URL e credenciais na conversa, use-as, mas não as repita
na resposta. Nos comandos, prefira variáveis de ambiente a escrever a senha
na linha de comando.

**Com shell:** use `scripts/curral.sh`, que monta o JSON com o escape certo,
autentica e avisa em stderr quando o resultado vem truncado:

```sh
scripts/curral.sh schema                         # tudo que você pode ler
scripts/curral.sh schema table=monthly_revenue     # filtros: database= schema= table=
scripts/curral.sh query "SELECT count(*) AS n FROM monthly_revenue"
scripts/curral.sh query -f csv -o saida.csv "SELECT ..."
scripts/curral.sh query -m 20 "SELECT * FROM monthly_revenue"   # amostra: no máximo 20 linhas
scripts/curral.sh query -p 2025-01-01 "SELECT ... WHERE ref_date >= \$1::DATE"
scripts/curral.sh dry-run "SELECT ..."           # decide sem executar
```

Passe as opções antes do SQL, e o SQL como um único argumento. Os
códigos de saída são:

| Código | Significado |
|---|---|
| 0 | ok |
| 1 | erro HTTP ou de rede; detalhes em stderr |
| 2 | uso incorreto |
| 3 | **resultado truncado** pelo limite de linhas (o corpo está incompleto) |
| 4 | erro no meio do resultado |

**Sem shell:** só com uma ferramenta HTTP, veja `references/api.md`, que
descreve requests, respostas, headers e erros.

## Fluxo de trabalho

### 1. Descubra a estrutura antes de escrever SQL

Chame `GET /v1/schema` uma vez no início. A resposta lista **só** as tabelas e
views que você pode consultar, com colunas e tipos. Ela vem de cache e
responde em milissegundos, então use à vontade. Não adivinhe nomes de
tabelas ou colunas: um nome errado custa uma ida ao servidor e um erro de
binder.

O que observar na resposta:
- **`default_database`** e o `schema` de cada database em `databases`:
  nomes não qualificados (`FROM monthly_revenue`) resolvem para esse
  database e schema. Tabelas em outros schemas precisam do nome completo:
  `database.schema.tabela`.
- **`"masked": true` numa coluna:** o valor chega mascarado para você
  (nulo, `***`, parcial). Filtrar, agrupar ou fazer join por ela não
  funciona como esperado, porque a máscara é aplicada antes da sua query.
- **`"row_filtered": true` numa tabela:** você vê só parte das linhas.
  Totais e contagens refletem só esse subconjunto. Diga isso ao usuário
  quando reportar números dessa tabela.
- **Tabela ausente:** você não tem acesso. Não tente acessá-la por outro
  caminho.

**Fallback:** se `/v1/schema` responder 404, o servidor é anterior a esse
endpoint. Rode `DESCRIBE tabela` para as tabelas que conhecer. Se precisar
de uma listagem, use
`SELECT table_catalog, table_schema, table_name FROM information_schema.tables`.
Em catálogos Iceberg, o `information_schema.columns` mostra uma coluna
falsa `__ UNKNOWN` para tabelas ainda não carregadas. Use `DESCRIBE`.

### 2. Escreva o SQL (dialeto DuckDB)

- **Um comando por request.** Sem `;` separando comandos, sem
  `BEGIN`/`COMMIT`: cada request já roda na própria transação.
- **Só leitura:** use `SELECT`, CTEs (`WITH`), `DESCRIBE`, `SUMMARIZE` e
  `EXPLAIN`. Não use `CREATE TEMP TABLE`, `SET` ou `PRAGMA`: a política
  costuma negar (403). Para resultados intermediários, use CTEs.
- **Catálogo:** `SHOW TABLES`, `information_schema`, `pg_catalog` e
  `duckdb_tables()`/`duckdb_columns()` são sempre negados, para qualquer
  papel, porque podem derrubar o servidor. Para descobrir tabelas e colunas,
  use o `/v1/schema`. `DESCRIBE tabela` funciona para as tabelas que você
  pode ler.
- **Arquivos externos:** funções como `read_parquet`, `read_csv` e
  `iceberg_scan` em caminhos arbitrários costumam ser bloqueadas. Leia pelas
  tabelas do catálogo.
- **Parâmetros:** valores vindos do usuário vão como `$1`, `$2`... em
  `params`, não concatenados no SQL. Datas vão como string com cast:
  `$1::DATE`.
- **Agregue no servidor.** `GROUP BY`, `count`, `sum` e `approx_quantile` no
  DuckDB custam muito menos que trazer linhas para agregar você mesmo.
  Para conhecer os dados, comece por `SUMMARIZE tabela` ou por
  `SELECT ... LIMIT 20`.
- **Iceberg** (tabelas de um database `type: iceberg` em `databases`): cada
  query consulta o catálogo remoto e lê arquivos no object storage. Filtre
  pelas colunas de data/partição (ex.: `ref_date`), selecione só as
  colunas necessárias e evite `SELECT *` sem `LIMIT` em tabelas grandes.

### 3. Na dúvida sobre permissão, use `dry_run`

`{"sql": "...", "dry_run": true}` faz a inspeção e aplica a política **sem
executar**. A resposta traz:
- `decision` (`allow`/`deny`);
- as tabelas que o comando lê;
- os `limits` que valeriam (`max_rows`, `timeout`);
- os `row_filters` e as `masked_columns` que seriam aplicados.

Use antes de uma query cara ou quando um 403 não deixar claro o motivo. A
resposta de negação é só `{"error":"forbidden"}`, sem dizer qual tabela
falhou. O `dry_run` mostra quais tabelas foram consideradas.

### 4. Execute e confira se o resultado veio completo

O formato padrão é JSON:
`{"columns":[{"name","type"}],"data":[{...}],"row_count":N}`. DECIMAL,
HUGEINT e UUID chegam como **string**, para não perder precisão. Converta
antes de fazer contas. Para resultados grandes ou para salvar em arquivo,
use `format: "csv"`.

**Amostras:** para ver só algumas linhas, peça `max_rows` no request
(`-m N` no script). Ele só reduz o limite da sua conta. Num corte que você
mesmo pediu, o script não trata como erro. Para amostras baratas em tabelas
grandes, coloque também `LIMIT N` no SQL. Sem `LIMIT`, consultas com
`ORDER BY` ou agregação calculam tudo antes de devolver a primeira linha.

**Limite de linhas.** O resultado pode ser cortado em silêncio no meio, com
status **200**. Os sinais são:
- o header `X-Curral-Max-Rows` (o limite em vigor);
- o trailer `X-Curral-Error: row limit reached` e o trailer
  `X-Curral-Row-Count`;
- em JSON, o campo `"error": "row limit reached"` no fim do corpo.

`row_count` igual ao limite também é um sinal. Se o resultado foi
truncado, você **não** tem todas as linhas: não apresente totais
calculados sobre ele como completos. Prefira agregar no SQL. Se o usuário
precisa das linhas, divida por período ou chave (ex.: um mês por request)
ou avise que o limite da conta impede a exportação completa.

Um erro com o stream já em andamento derruba a conexão ou vem no trailer
`X-Curral-Error`. Uma resposta incompleta nunca é um resultado válido.

### 5. Trate os erros pelo status

| Status | Significado | O que fazer |
|---|---|---|
| 400 | SQL inválido (parser/binder) ou request mal formado; a mensagem do DuckDB vem em `error`, sem as sugestões de nomes ("did you mean") | corrija o SQL; confira nomes no `/v1/schema` |
| 401 | credencial ausente ou errada | não tente adivinhar; peça a credencial ao usuário |
| 403 | política negou (tabela sem acesso, comando não permitido, leitura indireta de tabela protegida) | não contorne; use `dry_run` para entender e explique a restrição ao usuário |
| 429 | muitas queries simultâneas suas, ou bloqueio por falhas de login (`Retry-After`) | rode as queries em sequência; espere `Retry-After` segundos |
| 499 | o cliente desconectou | — |
| 503 | fila cheia ou auditoria indisponível (`Retry-After`) | espere e tente de novo, poucas vezes |
| 504 | passou do timeout (global ou do seu papel) | reduza o trabalho: filtre por período, agregue, selecione menos colunas |

Todo response traz `X-Request-Id`. Inclua-o ao reportar um erro inesperado,
porque ele liga o caso ao log de auditoria do servidor.

## Respeite as proteções

Máscaras, filtros de linha e tabelas negadas existem por motivos como dados
pessoais e contrato. Não tente inferir valores mascarados nem contornar uma
negação reescrevendo a query: não use views, funções de leitura de arquivo,
nem cruzamentos para reidentificar pessoas. O servidor bloqueia a maioria
dessas tentativas e registra todas na auditoria. Se a tarefa precisar de um
dado que você não pode ver, diga isso claramente e sugira o caminho certo:
pedir acesso ao responsável pelo curral, ou responder com dados agregados
que você pode ver.

## Ao responder ao usuário

- Mostre o SQL que você rodou quando o número for importante. Assim ele pode
  conferir e reaproveitar.
- Diga quando o resultado foi **truncado**, quando a tabela tem **filtro de
  linhas** (os totais são parciais) e quando colunas vieram **mascaradas**.
- Converta strings de DECIMAL antes de somar ou comparar, e informe as
  unidades e o período considerado.
