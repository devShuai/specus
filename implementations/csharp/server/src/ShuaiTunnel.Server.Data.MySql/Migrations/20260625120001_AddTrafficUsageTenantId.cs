using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using ShuaiTunnel.Server.Data;

#nullable disable

namespace ShuaiTunnel.Server.Data.MySql.Migrations
{
    [DbContext(typeof(TunnelDbContext))]
    [Migration("20260625120001_AddTrafficUsageTenantId")]
    public partial class AddTrafficUsageTenantId : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "tenant_id",
                table: "tunnel_traffic_usage",
                type: "varchar(80)",
                maxLength: 80,
                nullable: false,
                defaultValue: "");

            migrationBuilder.CreateIndex(
                name: "idx_tunnel_traffic_client",
                table: "tunnel_traffic_usage",
                column: "client_id");

            migrationBuilder.CreateIndex(
                name: "idx_tunnel_traffic_tenant",
                table: "tunnel_traffic_usage",
                column: "tenant_id");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "idx_tunnel_traffic_tenant",
                table: "tunnel_traffic_usage");

            migrationBuilder.DropIndex(
                name: "idx_tunnel_traffic_client",
                table: "tunnel_traffic_usage");

            migrationBuilder.DropColumn(
                name: "tenant_id",
                table: "tunnel_traffic_usage");
        }
    }
}
