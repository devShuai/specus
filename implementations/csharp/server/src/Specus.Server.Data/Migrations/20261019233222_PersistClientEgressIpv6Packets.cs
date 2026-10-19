using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Specus.Server.Data.Migrations
{
    /// <inheritdoc />
    public partial class PersistClientEgressIpv6Packets : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "client_egress_ipv6_packets",
                table: "specus_client_session",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Binary rollback keeps this additive column and its per-session declarations.
            // Refuse before any DDL/history change, including a rollback past older guards.
            throw new NotSupportedException("IPv6 packet declarations must be retained; roll back the binary without downgrading the database.");
        }
    }
}
