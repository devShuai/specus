using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Specus.Server.Data;

#nullable disable

namespace Specus.Server.Data.MySql.Migrations;

[DbContext(typeof(SpecusDbContext))]
[Migration("20260818090001_AddClientPackageCatalogue")]
public partial class AddClientPackageCatalogue : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<string>("version", "client_download_link", type: "varchar(32)",
            maxLength: 32, nullable: true);
        migrationBuilder.AddColumn<string>("sha256", "client_download_link", type: "varchar(64)",
            maxLength: 64, nullable: true);
        migrationBuilder.AddColumn<long>("file_size", "client_download_link", type: "bigint",
            nullable: false, defaultValue: 0L);
        migrationBuilder.AddColumn<bool>("is_latest", "client_download_link", type: "tinyint(1)",
            nullable: false, defaultValue: false);
        migrationBuilder.AddColumn<string>("latest_slot", "client_download_link", type: "varchar(104)",
            maxLength: 104, nullable: true);
        migrationBuilder.AddColumn<string>("changelog_url", "client_download_link", type: "varchar(1024)",
            maxLength: 1024, nullable: true);
        migrationBuilder.AddColumn<string>("min_supported_version", "client_download_link", type: "varchar(32)",
            maxLength: 32, nullable: true);
        migrationBuilder.CreateIndex("uq_client_download_version", "client_download_link",
            ["implementation", "platform", "arch", "version"], unique: true);
        migrationBuilder.CreateIndex("uq_client_download_latest_slot", "client_download_link",
            "latest_slot", unique: true);
        migrationBuilder.CreateIndex("idx_client_download_latest", "client_download_link",
            ["implementation", "platform", "arch", "is_latest", "enabled"]);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropIndex("uq_client_download_version", "client_download_link");
        migrationBuilder.DropIndex("uq_client_download_latest_slot", "client_download_link");
        migrationBuilder.DropIndex("idx_client_download_latest", "client_download_link");
        migrationBuilder.DropColumn("version", "client_download_link");
        migrationBuilder.DropColumn("sha256", "client_download_link");
        migrationBuilder.DropColumn("file_size", "client_download_link");
        migrationBuilder.DropColumn("is_latest", "client_download_link");
        migrationBuilder.DropColumn("latest_slot", "client_download_link");
        migrationBuilder.DropColumn("changelog_url", "client_download_link");
        migrationBuilder.DropColumn("min_supported_version", "client_download_link");
    }
}
