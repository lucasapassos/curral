package engine

import (
	"fmt"

	duckdb "github.com/duckdb/duckdb-go/v2"
)

// describeStmt reads the result columns of res and the parameter types of
// params, both prepared but not run.
func describeStmt(res, params *duckdb.Stmt) (Description, error) {
	n, err := res.ColumnCount()
	if err != nil {
		return Description{}, err
	}
	d := Description{Columns: make([]Column, n)}
	for i := range n {
		if d.Columns[i].Name, err = res.ColumnName(i); err != nil {
			return Description{}, err
		}
		if info, err := res.ColumnTypeInfo(i); err == nil {
			d.Columns[i].Type = duckTypeName(info)
		}
	}
	for i := 1; i <= params.NumInput(); i++ {
		t, _ := params.ParamType(i)
		d.Params = append(d.Params, scalarTypeNames[t])
	}
	return d, nil
}

// duckTypeName names a type as DuckDB does for scalar types and decimals,
// and by kind (LIST, STRUCT...) for the rest.
func duckTypeName(info duckdb.TypeInfo) string {
	if alias := info.Alias(); alias != "" {
		return alias // JSON, INET...
	}
	if d, ok := info.Details().(*duckdb.DecimalDetails); ok {
		return fmt.Sprintf("DECIMAL(%d,%d)", d.Width, d.Scale)
	}
	return scalarTypeNames[info.InternalType()]
}

var scalarTypeNames = map[duckdb.Type]string{
	duckdb.TYPE_BOOLEAN:      "BOOLEAN",
	duckdb.TYPE_TINYINT:      "TINYINT",
	duckdb.TYPE_SMALLINT:     "SMALLINT",
	duckdb.TYPE_INTEGER:      "INTEGER",
	duckdb.TYPE_BIGINT:       "BIGINT",
	duckdb.TYPE_UTINYINT:     "UTINYINT",
	duckdb.TYPE_USMALLINT:    "USMALLINT",
	duckdb.TYPE_UINTEGER:     "UINTEGER",
	duckdb.TYPE_UBIGINT:      "UBIGINT",
	duckdb.TYPE_HUGEINT:      "HUGEINT",
	duckdb.TYPE_UHUGEINT:     "UHUGEINT",
	duckdb.TYPE_FLOAT:        "FLOAT",
	duckdb.TYPE_DOUBLE:       "DOUBLE",
	duckdb.TYPE_DECIMAL:      "DECIMAL",
	duckdb.TYPE_VARCHAR:      "VARCHAR",
	duckdb.TYPE_BLOB:         "BLOB",
	duckdb.TYPE_UUID:         "UUID",
	duckdb.TYPE_DATE:         "DATE",
	duckdb.TYPE_TIME:         "TIME",
	duckdb.TYPE_TIME_TZ:      "TIME WITH TIME ZONE",
	duckdb.TYPE_TIMESTAMP:    "TIMESTAMP",
	duckdb.TYPE_TIMESTAMP_TZ: "TIMESTAMP WITH TIME ZONE",
	duckdb.TYPE_TIMESTAMP_S:  "TIMESTAMP_S",
	duckdb.TYPE_TIMESTAMP_MS: "TIMESTAMP_MS",
	duckdb.TYPE_TIMESTAMP_NS: "TIMESTAMP_NS",
	duckdb.TYPE_INTERVAL:     "INTERVAL",
	duckdb.TYPE_ENUM:         "ENUM",
	duckdb.TYPE_LIST:         "LIST",
	duckdb.TYPE_STRUCT:       "STRUCT",
	duckdb.TYPE_MAP:          "MAP",
	duckdb.TYPE_ARRAY:        "ARRAY",
	duckdb.TYPE_UNION:        "UNION",
	duckdb.TYPE_BIT:          "BIT",
}
