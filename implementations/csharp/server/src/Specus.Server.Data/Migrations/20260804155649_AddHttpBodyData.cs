using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Specus.Server.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddHttpBodyData : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<byte[]>(
                name: "request_body_data",
                table: "specus_http_traffic_exchange",
                type: "BLOB",
                nullable: true);

            migrationBuilder.AddColumn<byte[]>(
                name: "response_body_data",
                table: "specus_http_traffic_exchange",
                type: "BLOB",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "request_body_data",
                table: "specus_http_traffic_exchange");

            migrationBuilder.DropColumn(
                name: "response_body_data",
                table: "specus_http_traffic_exchange");
        }
    }
}
