using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Specus.Server.Data;

#nullable disable

namespace Specus.Server.Data.Postgres.Migrations
{
    [DbContext(typeof(SpecusDbContext))]
    [Migration("20260625130002_AddPeerMeshSchema")]
    public partial class AddPeerMeshSchema : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "peer_mesh_acl",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false),
                    tenant_id = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: false),
                    owner_username = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: false),
                    source_client_id = table.Column<long>(type: "bigint", nullable: false),
                    source_client_name = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: false),
                    target_client_id = table.Column<long>(type: "bigint", nullable: false),
                    target_client_name = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: false),
                    allowed = table.Column<bool>(type: "boolean", nullable: false),
                    created_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    updated_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_peer_mesh_acl", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "peer_mesh_device",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false),
                    tenant_id = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: false),
                    owner_username = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: false),
                    client_id = table.Column<long>(type: "bigint", nullable: false),
                    client_name = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: false),
                    virtual_ip = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    cidr = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    public_key = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    nat_type = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true),
                    last_endpoint = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    virtual_device_mode = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true),
                    virtual_device_name = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true),
                    virtual_device_status = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true),
                    virtual_device_error = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    virtual_device_updated_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: true),
                    enabled = table.Column<bool>(type: "boolean", nullable: false),
                    last_seen_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: true),
                    created_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    updated_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_peer_mesh_device", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "peer_mesh_session",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false),
                    tenant_id = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: false),
                    source_client_id = table.Column<long>(type: "bigint", nullable: false),
                    source_client_name = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: false),
                    target_client_id = table.Column<long>(type: "bigint", nullable: false),
                    target_client_name = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: false),
                    path_type = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    status = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    token_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    started_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    updated_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    expires_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    closed_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: true),
                    rtt_millis = table.Column<long>(type: "bigint", nullable: true),
                    local_endpoint = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    remote_endpoint = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    direct_bytes = table.Column<long>(type: "bigint", nullable: false),
                    relay_bytes = table.Column<long>(type: "bigint", nullable: false),
                    last_traffic_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_peer_mesh_session", x => x.Id);
                });

            migrationBuilder.CreateIndex("idx_peer_mesh_acl_source", "peer_mesh_acl", new[] { "tenant_id", "source_client_id" });
            migrationBuilder.CreateIndex("idx_peer_mesh_acl_target", "peer_mesh_acl", new[] { "tenant_id", "target_client_id" });
            migrationBuilder.CreateIndex("uk_peer_mesh_acl_pair", "peer_mesh_acl", new[] { "tenant_id", "source_client_id", "target_client_id" }, unique: true);
            migrationBuilder.CreateIndex("idx_peer_mesh_device_client_name", "peer_mesh_device", "client_name");
            migrationBuilder.CreateIndex("idx_peer_mesh_device_owner", "peer_mesh_device", new[] { "tenant_id", "owner_username" });
            migrationBuilder.CreateIndex("uk_peer_mesh_device_client", "peer_mesh_device", new[] { "tenant_id", "client_id" }, unique: true);
            migrationBuilder.CreateIndex("uk_peer_mesh_device_ip", "peer_mesh_device", new[] { "tenant_id", "virtual_ip" }, unique: true);
            migrationBuilder.CreateIndex("idx_peer_mesh_session_source", "peer_mesh_session", new[] { "tenant_id", "source_client_id" });
            migrationBuilder.CreateIndex("idx_peer_mesh_session_status", "peer_mesh_session", "status");
            migrationBuilder.CreateIndex("idx_peer_mesh_session_target", "peer_mesh_session", new[] { "tenant_id", "target_client_id" });
            migrationBuilder.CreateIndex("idx_peer_mesh_session_tenant", "peer_mesh_session", "tenant_id");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(name: "peer_mesh_acl");
            migrationBuilder.DropTable(name: "peer_mesh_device");
            migrationBuilder.DropTable(name: "peer_mesh_session");
        }
    }
}
