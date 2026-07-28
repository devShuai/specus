using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Specus.Server.Data.Migrations
{
    [DbContext(typeof(SpecusDbContext))]
    [Migration("20260625140000_AddClientDownloadLinks")]
    public partial class AddClientDownloadLinks : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "client_download_link",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false),
                    implementation = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    platform = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    arch = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    display_name = table.Column<string>(type: "TEXT", maxLength: 120, nullable: false),
                    download_url = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: false),
                    description = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
                    display_order = table.Column<int>(type: "INTEGER", nullable: false),
                    enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    created_at = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    updated_at = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_client_download_link", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "idx_client_download_impl",
                table: "client_download_link",
                column: "implementation");

            migrationBuilder.CreateIndex(
                name: "idx_client_download_order",
                table: "client_download_link",
                column: "display_order");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(name: "client_download_link");
        }
    }
}
