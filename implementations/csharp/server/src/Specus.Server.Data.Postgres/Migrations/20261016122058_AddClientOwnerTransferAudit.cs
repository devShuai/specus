using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Specus.Server.Data.Postgres.Migrations
{
    /// <inheritdoc />
    public partial class AddClientOwnerTransferAudit : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "client_owner_transfer_audit",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false),
                    tenant_id = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: false),
                    occurred_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    actor = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: false),
                    scope = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    path_id = table.Column<long>(type: "bigint", nullable: false),
                    target_username = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: false),
                    credential_id = table.Column<long>(type: "bigint", nullable: true),
                    detail_json = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_client_owner_transfer_audit", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "idx_owner_transfer_audit_tenant",
                table: "client_owner_transfer_audit",
                columns: new[] { "tenant_id", "id" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            throw new NotSupportedException("Downgrade would discard client ownership audit history; restore a verified backup instead.");
        }
    }
}
