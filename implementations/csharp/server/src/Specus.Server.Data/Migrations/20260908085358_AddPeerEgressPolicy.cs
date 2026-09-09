using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Specus.Server.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddPeerEgressPolicy : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "peer_mesh_egress_policy",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false),
                    tenant_id = table.Column<string>(type: "TEXT", maxLength: 80, nullable: false),
                    owner_username = table.Column<string>(type: "TEXT", maxLength: 80, nullable: false),
                    egress_client_id = table.Column<long>(type: "INTEGER", nullable: false),
                    egress_client_name = table.Column<string>(type: "TEXT", maxLength: 120, nullable: false),
                    enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    scope = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    allowed_consumer_client_ids = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    destination_rules = table.Column<string>(type: "TEXT", maxLength: 4096, nullable: false),
                    max_concurrent_flows = table.Column<int>(type: "INTEGER", nullable: false),
                    max_flows_per_consumer = table.Column<int>(type: "INTEGER", nullable: false),
                    idle_timeout_seconds = table.Column<int>(type: "INTEGER", nullable: false),
                    created_at = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    updated_at = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_peer_mesh_egress_policy", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "idx_peer_egress_policy_enabled",
                table: "peer_mesh_egress_policy",
                columns: new[] { "tenant_id", "enabled" });

            migrationBuilder.CreateIndex(
                name: "uk_peer_egress_policy_client",
                table: "peer_mesh_egress_policy",
                columns: new[] { "tenant_id", "egress_client_id" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "peer_mesh_egress_policy");
        }
    }
}
