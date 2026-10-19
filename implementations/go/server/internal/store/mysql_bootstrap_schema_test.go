package store

import (
	"strings"
	"testing"
)

func TestMySQLWorkbenchDDLIsTerminatedBeforeProductMetrics(t *testing.T) {
	script, err := schemaFS.ReadFile("schema/mysql.sql")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, statement := range splitStatements(string(script)) {
		if !strings.HasPrefix(statement, "CREATE TABLE IF NOT EXISTS management_workbench_item (") {
			continue
		}
		found = true
		if strings.Contains(statement, "CREATE TABLE IF NOT EXISTS product_metrics_switch") ||
			!strings.HasSuffix(statement, ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4") {
			t.Fatal("workbench DDL must close its table/engine statement before the next metrics CREATE")
		}
	}
	if !found {
		t.Fatal("workbench DDL missing")
	}
}
