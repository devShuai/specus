using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Specus.Server.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddTemporaryHttpShare : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "http_access_audit",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    tenant_id = table.Column<string>(type: "TEXT", maxLength: 80, nullable: false),
                    occurred_at = table.Column<long>(type: "INTEGER", nullable: false),
                    actor = table.Column<string>(type: "TEXT", maxLength: 120, nullable: true),
                    action = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    route_id = table.Column<long>(type: "INTEGER", nullable: false),
                    share_id = table.Column<string>(type: "TEXT", maxLength: 16, nullable: true),
                    detail_json = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_http_access_audit", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "http_share",
                columns: table => new
                {
                    share_id = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    tenant_id = table.Column<string>(type: "TEXT", maxLength: 80, nullable: false),
                    route_id = table.Column<long>(type: "INTEGER", nullable: false),
                    token_sha256 = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    access = table.Column<string>(type: "TEXT", maxLength: 8, nullable: false),
                    path_prefix = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    label = table.Column<string>(type: "TEXT", maxLength: 255, nullable: true),
                    created_by = table.Column<string>(type: "TEXT", maxLength: 120, nullable: false),
                    created_at = table.Column<long>(type: "INTEGER", nullable: false),
                    expires_at = table.Column<long>(type: "INTEGER", nullable: false),
                    revoked_at = table.Column<long>(type: "INTEGER", nullable: true),
                    revoked_by = table.Column<string>(type: "TEXT", maxLength: 120, nullable: true),
                    revoke_reason = table.Column<string>(type: "TEXT", maxLength: 40, nullable: true),
                    expiry_recorded = table.Column<sbyte>(type: "INTEGER", nullable: false, defaultValue: (sbyte)0)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_http_share", x => x.share_id);
                });

            migrationBuilder.CreateIndex(
                name: "idx_http_access_audit_at",
                table: "http_access_audit",
                column: "occurred_at");

            migrationBuilder.CreateIndex(
                name: "idx_http_access_audit_route",
                table: "http_access_audit",
                columns: new[] { "tenant_id", "route_id", "id" });

            migrationBuilder.CreateIndex(
                name: "idx_http_share_creator",
                table: "http_share",
                columns: new[] { "tenant_id", "created_by" });

            migrationBuilder.CreateIndex(
                name: "idx_http_share_expires",
                table: "http_share",
                column: "expires_at");

            migrationBuilder.CreateIndex(
                name: "idx_http_share_route",
                table: "http_share",
                column: "route_id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "http_access_audit");

            migrationBuilder.DropTable(
                name: "http_share");
        }
    }
}
