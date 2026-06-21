using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace ShuaiTunnel.Server.Data.Postgres.Migrations
{
    /// <inheritdoc />
    public partial class InitialSchema : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "http_route_mapping",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false),
                    client_id = table.Column<long>(type: "bigint", nullable: false),
                    client_name = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: false),
                    route = table.Column<string>(type: "character varying(60)", maxLength: 60, nullable: false),
                    target_base_url = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    enabled = table.Column<bool>(type: "boolean", nullable: false),
                    created_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    updated_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_http_route_mapping", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "tunnel_client_account",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false),
                    client_name = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: false),
                    password_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    enabled = table.Column<bool>(type: "boolean", nullable: false),
                    connection_rate_limit_per_minute = table.Column<int>(type: "integer", nullable: false),
                    created_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    updated_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tunnel_client_account", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "tunnel_connection_record",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    client_id = table.Column<long>(type: "bigint", nullable: true),
                    client_name = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: false),
                    channel_id = table.Column<string>(type: "character varying(160)", maxLength: 160, nullable: true),
                    remote_address = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    connected_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    disconnected_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: true),
                    success = table.Column<bool>(type: "boolean", nullable: false),
                    failure_reason = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    disconnect_reason = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tunnel_connection_record", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "tunnel_connection_stat",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    client_id = table.Column<long>(type: "bigint", nullable: true),
                    client_name = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: false),
                    stat_month = table.Column<string>(type: "character varying(7)", maxLength: 7, nullable: false),
                    total_count = table.Column<long>(type: "bigint", nullable: false),
                    success_count = table.Column<long>(type: "bigint", nullable: false),
                    failure_count = table.Column<long>(type: "bigint", nullable: false),
                    updated_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tunnel_connection_stat", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "tunnel_mapping",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false),
                    client_id = table.Column<long>(type: "bigint", nullable: false),
                    client_name = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: false),
                    listen_port = table.Column<int>(type: "integer", nullable: false),
                    target_address = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    target_port = table.Column<int>(type: "integer", nullable: false),
                    enabled = table.Column<bool>(type: "boolean", nullable: false),
                    created_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    updated_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tunnel_mapping", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "tunnel_traffic_usage",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    client_id = table.Column<long>(type: "bigint", nullable: false),
                    client_name = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: false),
                    usage_date = table.Column<string>(type: "character varying(10)", maxLength: 10, nullable: false),
                    upload_bytes = table.Column<long>(type: "bigint", nullable: false),
                    download_bytes = table.Column<long>(type: "bigint", nullable: false),
                    updated_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tunnel_traffic_usage", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_http_route_mapping_client_id",
                table: "http_route_mapping",
                column: "client_id");

            migrationBuilder.CreateIndex(
                name: "IX_http_route_mapping_client_id_route",
                table: "http_route_mapping",
                columns: new[] { "client_id", "route" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_tunnel_client_account_client_name",
                table: "tunnel_client_account",
                column: "client_name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "idx_tunnel_connection_client_time",
                table: "tunnel_connection_record",
                columns: new[] { "client_id", "connected_at" });

            migrationBuilder.CreateIndex(
                name: "idx_tunnel_connection_connected_at",
                table: "tunnel_connection_record",
                column: "connected_at");

            migrationBuilder.CreateIndex(
                name: "IX_tunnel_connection_stat_client_name",
                table: "tunnel_connection_stat",
                column: "client_name");

            migrationBuilder.CreateIndex(
                name: "IX_tunnel_connection_stat_client_name_stat_month",
                table: "tunnel_connection_stat",
                columns: new[] { "client_name", "stat_month" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_tunnel_mapping_client_id",
                table: "tunnel_mapping",
                column: "client_id");

            migrationBuilder.CreateIndex(
                name: "IX_tunnel_mapping_listen_port",
                table: "tunnel_mapping",
                column: "listen_port",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_tunnel_traffic_usage_client_id",
                table: "tunnel_traffic_usage",
                column: "client_id");

            migrationBuilder.CreateIndex(
                name: "IX_tunnel_traffic_usage_client_id_usage_date",
                table: "tunnel_traffic_usage",
                columns: new[] { "client_id", "usage_date" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "http_route_mapping");

            migrationBuilder.DropTable(
                name: "tunnel_client_account");

            migrationBuilder.DropTable(
                name: "tunnel_connection_record");

            migrationBuilder.DropTable(
                name: "tunnel_connection_stat");

            migrationBuilder.DropTable(
                name: "tunnel_mapping");

            migrationBuilder.DropTable(
                name: "tunnel_traffic_usage");
        }
    }
}
