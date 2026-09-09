using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Specus.Server.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddPeerEgressActivity : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "peer_mesh_egress_activity",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false),
                    tenant_id = table.Column<string>(type: "TEXT", maxLength: 80, nullable: false),
                    egress_client_id = table.Column<long>(type: "INTEGER", nullable: false),
                    egress_client_name = table.Column<string>(type: "TEXT", maxLength: 120, nullable: false),
                    session_id = table.Column<long>(type: "INTEGER", nullable: false),
                    revision = table.Column<long>(type: "INTEGER", nullable: false),
                    active_flows = table.Column<long>(type: "INTEGER", nullable: false),
                    total_flows = table.Column<long>(type: "INTEGER", nullable: false),
                    rejected_flows = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: false),
                    bytes_in = table.Column<long>(type: "INTEGER", nullable: false),
                    bytes_out = table.Column<long>(type: "INTEGER", nullable: false),
                    reported_at = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    created_at = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    updated_at = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_peer_mesh_egress_activity", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "uk_peer_egress_activity_client",
                table: "peer_mesh_egress_activity",
                columns: new[] { "tenant_id", "egress_client_id" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "peer_mesh_egress_activity");
        }
    }
}
