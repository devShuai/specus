using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Specus.Server.Data.MySql.Migrations
{
    /// <inheritdoc />
    public partial class AddManagementWorkbench : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "management_workbench_item",
                columns: table => new
                {
                    tenant_id = table.Column<string>(type: "varchar(80)", maxLength: 80, nullable: false),
                    username = table.Column<string>(type: "varchar(80)", maxLength: 80, nullable: false),
                    list = table.Column<string>(type: "varchar(16)", maxLength: 16, nullable: false),
                    kind = table.Column<string>(type: "varchar(32)", maxLength: 32, nullable: false),
                    object_id = table.Column<long>(type: "bigint", nullable: false),
                    at_ms = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_management_workbench_item", x => new { x.tenant_id, x.username, x.list, x.kind, x.object_id });
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateIndex(
                name: "idx_mwi_list_at",
                table: "management_workbench_item",
                columns: new[] { "list", "at_ms" });

            migrationBuilder.CreateIndex(
                name: "idx_mwi_object",
                table: "management_workbench_item",
                columns: new[] { "tenant_id", "kind", "object_id" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "management_workbench_item");
        }
    }
}
