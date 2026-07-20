using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ShuaiTunnel.Server.Data.MySql.Migrations
{
    /// <inheritdoc />
    public partial class AddTransferAttachmentQuota : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "transfer_attachment_download_usage",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false),
                    tenant_id = table.Column<string>(type: "varchar(80)", maxLength: 80, nullable: false),
                    username = table.Column<string>(type: "varchar(80)", maxLength: 80, nullable: false),
                    attachment_id = table.Column<long>(type: "bigint", nullable: false),
                    size_bytes = table.Column<long>(type: "bigint", nullable: false),
                    usage_month = table.Column<string>(type: "varchar(7)", maxLength: 7, nullable: false),
                    created_at = table.Column<string>(type: "varchar(40)", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_transfer_attachment_download_usage", x => x.id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateIndex(
                name: "idx_transfer_attachment_owner_status",
                table: "transfer_attachment",
                columns: new[] { "tenant_id", "owner_username", "status", "expires_at" });

            migrationBuilder.CreateIndex(
                name: "idx_attachment_download_usage_account_month",
                table: "transfer_attachment_download_usage",
                columns: new[] { "tenant_id", "username", "usage_month" });

            migrationBuilder.CreateIndex(
                name: "idx_attachment_download_usage_attachment",
                table: "transfer_attachment_download_usage",
                columns: new[] { "attachment_id", "created_at" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "transfer_attachment_download_usage");

            migrationBuilder.DropIndex(
                name: "idx_transfer_attachment_owner_status",
                table: "transfer_attachment");
        }
    }
}
