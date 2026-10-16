package store

import (
	"regexp"
	"strings"
	"testing"
)

// Native MySQL bootstrap exposed a missing workbench table terminator: the next CREATE TABLE
// became part of the same driver Exec. Check all embedded dialects, even in SQLite-only CI.
func TestEmbeddedSchemaTablesAreSeparateStatements(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			data, err := schemaFS.ReadFile("schema/" + dialect + ".sql")
			if err != nil {
				t.Fatal(err)
			}
			for index, statement := range splitStatements(string(data)) {
				if count := strings.Count(strings.ToUpper(statement), "CREATE TABLE"); count > 1 {
					t.Errorf("statement %d contains %d CREATE TABLE operations; missing table terminator", index+1, count)
				}
			}
		})
	}
}

func TestPostgresBooleanDefaultsUseBooleanLiterals(t *testing.T) {
	data, err := schemaFS.ReadFile("schema/postgres.sql")
	if err != nil {
		t.Fatal(err)
	}
	invalid := regexp.MustCompile(`(?i)\bBOOLEAN\s+(?:NOT\s+NULL\s+)?DEFAULT\s+[01]\b`)
	if invalid.Match(data) {
		t.Fatal("PostgreSQL boolean columns must not use integer default expressions")
	}
}
