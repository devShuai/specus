using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Specus.Server.Data.Postgres.Migrations
{
    /// <inheritdoc />
    public partial class AddPeerServiceDiscovery : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "peer_service_applications",
                table: "specus_client_session",
                type: "character varying(160)",
                maxLength: 160,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "peer_service_discovery_version",
                table: "specus_client_session",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.CreateTable(
                name: "peer_mesh_service_sharing",
                columns: table => new
                {
                    tenant_id = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: false),
                    enabled = table.Column<bool>(type: "boolean", nullable: false),
                    updated_by = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true),
                    updated_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_peer_mesh_service_sharing", x => x.tenant_id);
                });

            migrationBuilder.CreateTable(
                name: "peer_mesh_shared_service",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false),
                    tenant_id = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: false),
                    client_id = table.Column<long>(type: "bigint", nullable: false),
                    client_name = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: false),
                    service_id = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    name = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: false),
                    description = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    transport = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    application = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    target_host = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    target_port = table.Column<int>(type: "integer", nullable: false),
                    published_port = table.Column<int>(type: "integer", nullable: false),
                    path = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    enabled = table.Column<bool>(type: "boolean", nullable: false),
                    visibility = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    created_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    updated_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_peer_mesh_shared_service", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "idx_peer_shared_service_tenant_client",
                table: "peer_mesh_shared_service",
                columns: new[] { "tenant_id", "client_id" });

            migrationBuilder.CreateIndex(
                name: "uk_peer_shared_service_id",
                table: "peer_mesh_shared_service",
                columns: new[] { "tenant_id", "client_id", "service_id" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "peer_mesh_service_sharing");

            migrationBuilder.DropTable(
                name: "peer_mesh_shared_service");

            migrationBuilder.DropColumn(
                name: "peer_service_applications",
                table: "specus_client_session");

            migrationBuilder.DropColumn(
                name: "peer_service_discovery_version",
                table: "specus_client_session");
        }
    }
}
