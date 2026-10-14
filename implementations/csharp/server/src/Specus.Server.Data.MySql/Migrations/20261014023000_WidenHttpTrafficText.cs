using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Specus.Server.Data.MySql.Migrations;

public partial class WidenHttpTrafficText : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        foreach (var name in new[]
        {
            "request_headers", "response_headers", "request_preview_hex", "response_preview_hex",
        })
        {
            // MODIFY without charset/collation inherits the TABLE default, which can narrow a
            // legacy column with an explicit utf8mb4 charset to latin1. Preserve its actual
            // attributes from server metadata. Column names are the fixed list above, not input.
            // Quoted session-variable names work with the default MySql.Data connection settings.
            migrationBuilder.Sql($"""
                SET @`specus_276_ddl` = (
                    SELECT CONCAT('ALTER TABLE `specus_http_traffic_exchange` MODIFY COLUMN `{name}` LONGTEXT CHARACTER SET `',
                                  CHARACTER_SET_NAME, '` COLLATE `', COLLATION_NAME, '` NULL')
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'specus_http_traffic_exchange'
                      AND COLUMN_NAME = '{name}'
                );
                PREPARE specus_276_statement FROM @`specus_276_ddl`;
                EXECUTE specus_276_statement;
                DEALLOCATE PREPARE specus_276_statement;
                SET @`specus_276_ddl` = NULL;
                """);
        }
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        // Reintroducing the old VARCHAR layout cannot create a valid utf8mb4 table and could
        // truncate existing text. Refuse before emitting any destructive/narrowing operation.
        throw new NotSupportedException("WidenHttpTrafficText cannot be safely reverted to the row-overflowing VARCHAR layout.");
    }
}
