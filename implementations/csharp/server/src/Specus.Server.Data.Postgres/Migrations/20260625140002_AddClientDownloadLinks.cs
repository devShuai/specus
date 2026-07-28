using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Specus.Server.Data;

#nullable disable

namespace Specus.Server.Data.Postgres.Migrations
{
    [DbContext(typeof(SpecusDbContext))]
    [Migration("20260625140002_AddClientDownloadLinks")]
    public partial class AddClientDownloadLinks : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "client_download_link",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false),
                    implementation = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    platform = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    arch = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    display_name = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: false),
                    download_url = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: false),
                    description = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    display_order = table.Column<int>(type: "integer", nullable: false),
                    enabled = table.Column<bool>(type: "boolean", nullable: false),
                    created_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    updated_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_client_download_link", x => x.Id);
                });

            migrationBuilder.CreateIndex("idx_client_download_impl", "client_download_link", "implementation");
            migrationBuilder.CreateIndex("idx_client_download_order", "client_download_link", "display_order");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(name: "client_download_link");
        }
    }
}
