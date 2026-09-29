using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Specus.Server.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddClientEgressDomainTargets : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "client_egress_domain_targets",
                table: "specus_client_session",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "client_egress_domain_targets",
                table: "specus_client_session");
        }
    }
}
