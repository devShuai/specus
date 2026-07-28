using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Specus.Server.Data.MySql.Migrations
{
    /// <inheritdoc />
    public partial class AddSingleUseDownloadGrant : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "transfer_attachment_download_grant",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false),
                    token_hash = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false),
                    tenant_id = table.Column<string>(type: "varchar(80)", maxLength: 80, nullable: false),
                    username = table.Column<string>(type: "varchar(80)", maxLength: 80, nullable: false),
                    attachment_id = table.Column<long>(type: "bigint", nullable: false),
                    created_at = table.Column<string>(type: "varchar(40)", maxLength: 40, nullable: false),
                    expires_at = table.Column<string>(type: "varchar(40)", maxLength: 40, nullable: false),
                    consumed_at = table.Column<string>(type: "varchar(40)", maxLength: 40, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_transfer_attachment_download_grant", x => x.id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateIndex(
                name: "idx_attachment_download_grant_attachment",
                table: "transfer_attachment_download_grant",
                columns: new[] { "attachment_id", "created_at" });

            migrationBuilder.CreateIndex(
                name: "idx_attachment_download_grant_expiry",
                table: "transfer_attachment_download_grant",
                columns: new[] { "expires_at", "consumed_at" });

            migrationBuilder.CreateIndex(
                name: "IX_transfer_attachment_download_grant_token_hash",
                table: "transfer_attachment_download_grant",
                column: "token_hash",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "transfer_attachment_download_grant");
        }
    }
}
