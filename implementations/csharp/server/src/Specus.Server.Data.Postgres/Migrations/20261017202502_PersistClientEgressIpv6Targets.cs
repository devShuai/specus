using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Specus.Server.Data.Postgres.Migrations
{
    /// <inheritdoc />
    public partial class PersistClientEgressIpv6Targets : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "client_egress_ipv6_targets",
                table: "specus_client_session",
                type: "boolean",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Binary rollback keeps this additive column and its per-session declarations.
            // Refuse before any DDL/history change, including a rollback past older guards.
            throw new NotSupportedException("IPv6 target declarations must be retained; roll back the binary without downgrading the database.");
        }
    }
}
