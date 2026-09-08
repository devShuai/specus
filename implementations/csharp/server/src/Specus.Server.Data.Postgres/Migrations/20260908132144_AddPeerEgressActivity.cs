using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Specus.Server.Data.Postgres.Migrations
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
                    Id = table.Column<long>(type: "bigint", nullable: false),
                    tenant_id = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: false),
                    egress_client_id = table.Column<long>(type: "bigint", nullable: false),
                    egress_client_name = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: false),
                    session_id = table.Column<long>(type: "bigint", nullable: false),
                    revision = table.Column<long>(type: "bigint", nullable: false),
                    active_flows = table.Column<long>(type: "bigint", nullable: false),
                    total_flows = table.Column<long>(type: "bigint", nullable: false),
                    rejected_flows = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: false),
                    bytes_in = table.Column<long>(type: "bigint", nullable: false),
                    bytes_out = table.Column<long>(type: "bigint", nullable: false),
                    reported_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    created_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    updated_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false)
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
