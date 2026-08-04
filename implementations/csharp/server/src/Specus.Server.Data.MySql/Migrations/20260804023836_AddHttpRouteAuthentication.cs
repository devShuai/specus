using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Specus.Server.Data.MySql.Migrations
{
    /// <inheritdoc />
    public partial class AddHttpRouteAuthentication : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "auth_enabled",
                table: "http_route_mapping",
                type: "tinyint(1)",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<string>(
                name: "auth_password_hash",
                table: "http_route_mapping",
                type: "varchar(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "auth_username",
                table: "http_route_mapping",
                type: "varchar(120)",
                maxLength: 120,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "auth_enabled",
                table: "http_route_mapping");

            migrationBuilder.DropColumn(
                name: "auth_password_hash",
                table: "http_route_mapping");

            migrationBuilder.DropColumn(
                name: "auth_username",
                table: "http_route_mapping");
        }
    }
}
