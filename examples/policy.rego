# Example authorization policy for curral.
#
# input:
#   user            "analyst"
#   roles           ["analyst"]
#   sql             the statement text
#   statement_type  SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, ALTER, EXPLAIN, PRAGMA, ...
#   database        catalog used for unqualified names
#   tables          ["sales.main.orders"]  every table/view base table read (resolved by DuckDB)
#   targets         ["sales.main.orders"]  objects written, created or dropped
#   functions       ["read_parquet"]       table functions used as sources (not tables!)
#   databases       catalogs touched by tables + targets
#   resolved        false when tables/targets could not be fully determined
#
# Row filters (who sees which rows) live in the --row-filters file; see
# examples/rls.yaml.
#
# data.roles comes from roles.json (pass it with another --policy flag).
package curral

import rego.v1

default allow := false

# Admins can run anything.
allow if "admin" in input.roles

# Read-only statements over readable databases.
allow if {
	safe_sources
	input.statement_type in {"SELECT", "EXPLAIN"}
	count(input.targets) == 0
}

# Data changes on writable databases (DDL stays with admins).
allow if {
	safe_sources
	input.statement_type in {"INSERT", "UPDATE", "DELETE"}
	count(input.targets) > 0
	every t in input.targets { writable(t) }
}

# Conditions shared by every non-admin rule: a known role, a fully resolved
# statement, readable tables, no denied table and only allowed table functions
# (functions such as read_parquet/read_csv bypass table grants).
safe_sources if {
	some role in input.roles
	data.roles[role]
	input.resolved
	every t in input.tables { readable(t) }
	every f in input.functions { f in data.allowed_functions }
	not denied_table
}

db_of(name) := split(name, ".")[0]

grants(kind, db) if {
	some role in input.roles
	some granted in data.roles[role][kind]
	granted in {db, "*"}
}

readable(table) if grants("read", db_of(table))

readable(table) if writable(table)

writable(table) if grants("write", db_of(table))

denied_table if {
	some t in array.concat(input.tables, input.targets)
	some role in input.roles
	t in data.roles[role].deny_tables
}

# Optional per-request limits, enabled with --policy-limits-query data.curral.limits.
# Evaluated only after allow; an undefined result means no limits. The global
# --query-timeout and --max-rows still cap everything.
#   timeout, max_rows: this request
#   max_concurrency:   queries this user may run at once (over it: 429);
#                      add "concurrency_group": "role:analyst" to share one
#                      quota among every analyst instead
limits := data.roles[role].limits if {
	not "admin" in input.roles
	count(input.roles) == 1
	role := input.roles[0]
}

# Optional column masks, enabled with --policy-masks-query data.curral.masks:
# {table: {column: mask}}, with mask "null", "redact", "last:N" or {"sql": "..."}.
# Masked values are computed before the user's query sees the table, so it
# cannot filter, join or group on the real values.
masks := data.masks if {
	not "admin" in input.roles
	not "pii_reader" in input.roles
}
