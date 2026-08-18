using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Specus.Server.Data.Migrations;

[DbContext(typeof(SpecusDbContext))]
[Migration("20260818090000_AddClientPackageCatalogue")]
public partial class AddClientPackageCatalogue : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<string>("version", "client_download_link", type: "TEXT",
            maxLength: 32, nullable: true);
        migrationBuilder.AddColumn<string>("sha256", "client_download_link", type: "TEXT",
            maxLength: 64, nullable: true);
        migrationBuilder.AddColumn<long>("file_size", "client_download_link", type: "INTEGER",
            nullable: false, defaultValue: 0L);
        migrationBuilder.AddColumn<bool>("is_latest", "client_download_link", type: "INTEGER",
            nullable: false, defaultValue: false);
        migrationBuilder.AddColumn<string>("changelog_url", "client_download_link", type: "TEXT",
            maxLength: 1024, nullable: true);
        migrationBuilder.AddColumn<string>("min_supported_version", "client_download_link", type: "TEXT",
            maxLength: 32, nullable: true);
        migrationBuilder.CreateIndex("uq_client_download_version", "client_download_link",
            ["implementation", "platform", "arch", "version"], unique: true);
        migrationBuilder.CreateIndex("idx_client_download_latest", "client_download_link",
            ["implementation", "platform", "arch", "is_latest", "enabled"]);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropIndex("uq_client_download_version", "client_download_link");
        migrationBuilder.DropIndex("idx_client_download_latest", "client_download_link");
        migrationBuilder.DropColumn("version", "client_download_link");
        migrationBuilder.DropColumn("sha256", "client_download_link");
        migrationBuilder.DropColumn("file_size", "client_download_link");
        migrationBuilder.DropColumn("is_latest", "client_download_link");
        migrationBuilder.DropColumn("changelog_url", "client_download_link");
        migrationBuilder.DropColumn("min_supported_version", "client_download_link");
    }
}
