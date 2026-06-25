using Microsoft.EntityFrameworkCore.Migrations;
using MySql.EntityFrameworkCore.Metadata;

#nullable disable

namespace ShuaiTunnel.Server.Data.MySql.Migrations
{
    /// <inheritdoc />
    public partial class AddManagementAndTrafficDetailSchema : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "detail_capture_enabled",
                table: "tunnel_mapping",
                type: "tinyint(1)",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "detail_capture_enabled",
                table: "http_route_mapping",
                type: "tinyint(1)",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "path_rewrite_enabled",
                table: "http_route_mapping",
                type: "tinyint(1)",
                nullable: false,
                defaultValue: false);

            migrationBuilder.CreateTable(
                name: "tunnel_http_traffic_exchange",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("MySQL:ValueGenerationStrategy", MySQLValueGenerationStrategy.IdentityColumn),
                    tenant_id = table.Column<string>(type: "varchar(80)", maxLength: 80, nullable: false),
                    client_id = table.Column<long>(type: "bigint", nullable: false),
                    client_name = table.Column<string>(type: "varchar(120)", maxLength: 120, nullable: false),
                    route = table.Column<string>(type: "varchar(128)", maxLength: 128, nullable: false),
                    resource_id = table.Column<long>(type: "bigint", nullable: true),
                    resource_name = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true),
                    method = table.Column<string>(type: "varchar(16)", maxLength: 16, nullable: false),
                    relative_path = table.Column<string>(type: "varchar(1024)", maxLength: 1024, nullable: false),
                    raw_query = table.Column<string>(type: "varchar(2048)", maxLength: 2048, nullable: true),
                    status_code = table.Column<int>(type: "int", nullable: false),
                    success = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    error = table.Column<string>(type: "varchar(2048)", maxLength: 2048, nullable: true),
                    remote_address = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true),
                    request_bytes = table.Column<long>(type: "bigint", nullable: false),
                    response_bytes = table.Column<long>(type: "bigint", nullable: false),
                    elapsed_ms = table.Column<long>(type: "bigint", nullable: false),
                    request_content_type = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true),
                    response_content_type = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true),
                    response_body_type = table.Column<string>(type: "varchar(32)", maxLength: 32, nullable: false),
                    request_headers = table.Column<string>(type: "varchar(8192)", maxLength: 8192, nullable: true),
                    response_headers = table.Column<string>(type: "varchar(8192)", maxLength: 8192, nullable: true),
                    request_preview_hex = table.Column<string>(type: "varchar(4096)", maxLength: 4096, nullable: true),
                    request_preview_text = table.Column<string>(type: "longtext", nullable: true),
                    response_preview_hex = table.Column<string>(type: "varchar(4096)", maxLength: 4096, nullable: true),
                    response_preview_text = table.Column<string>(type: "longtext", nullable: true),
                    request_truncated = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    response_truncated = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    captured_at = table.Column<string>(type: "varchar(40)", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tunnel_http_traffic_exchange", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "tunnel_management_user",
                columns: table => new
                {
                    username = table.Column<string>(type: "varchar(80)", maxLength: 80, nullable: false),
                    tenant_id = table.Column<string>(type: "varchar(80)", maxLength: 80, nullable: false),
                    password_hash = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false),
                    role = table.Column<string>(type: "varchar(20)", maxLength: 20, nullable: false),
                    enabled = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    created_at = table.Column<string>(type: "varchar(40)", maxLength: 40, nullable: false),
                    updated_at = table.Column<string>(type: "varchar(40)", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tunnel_management_user", x => x.username);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "tunnel_resource_traffic_usage",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("MySQL:ValueGenerationStrategy", MySQLValueGenerationStrategy.IdentityColumn),
                    tenant_id = table.Column<string>(type: "varchar(80)", maxLength: 80, nullable: false),
                    client_id = table.Column<long>(type: "bigint", nullable: false),
                    client_name = table.Column<string>(type: "varchar(120)", maxLength: 120, nullable: false),
                    resource_type = table.Column<string>(type: "varchar(32)", maxLength: 32, nullable: false),
                    resource_key = table.Column<string>(type: "varchar(128)", maxLength: 128, nullable: false),
                    resource_id = table.Column<long>(type: "bigint", nullable: true),
                    resource_name = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    usage_date = table.Column<string>(type: "varchar(10)", maxLength: 10, nullable: false),
                    upload_bytes = table.Column<long>(type: "bigint", nullable: false),
                    download_bytes = table.Column<long>(type: "bigint", nullable: false),
                    updated_at = table.Column<string>(type: "varchar(40)", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tunnel_resource_traffic_usage", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "tunnel_tcp_traffic_frame",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("MySQL:ValueGenerationStrategy", MySQLValueGenerationStrategy.IdentityColumn),
                    tenant_id = table.Column<string>(type: "varchar(80)", maxLength: 80, nullable: false),
                    client_id = table.Column<long>(type: "bigint", nullable: false),
                    client_name = table.Column<string>(type: "varchar(120)", maxLength: 120, nullable: false),
                    listen_port = table.Column<int>(type: "int", nullable: false),
                    resource_id = table.Column<long>(type: "bigint", nullable: true),
                    resource_name = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true),
                    channel_id = table.Column<string>(type: "varchar(120)", maxLength: 120, nullable: false),
                    frame_direction = table.Column<string>(type: "varchar(32)", maxLength: 32, nullable: false),
                    remote_address = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true),
                    source_address = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true),
                    source_port = table.Column<int>(type: "int", nullable: true),
                    destination_address = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true),
                    destination_port = table.Column<int>(type: "int", nullable: true),
                    stream_offset = table.Column<long>(type: "bigint", nullable: false),
                    stream_end_offset = table.Column<long>(type: "bigint", nullable: false),
                    frame_index = table.Column<long>(type: "bigint", nullable: false),
                    payload_bytes = table.Column<long>(type: "bigint", nullable: false),
                    payload_data = table.Column<byte[]>(type: "longblob", nullable: false),
                    payload_preview_hex = table.Column<string>(type: "varchar(4096)", maxLength: 4096, nullable: true),
                    payload_preview_text = table.Column<string>(type: "varchar(4096)", maxLength: 4096, nullable: true),
                    truncated = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    frame_time = table.Column<string>(type: "varchar(40)", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tunnel_tcp_traffic_frame", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateIndex(
                name: "idx_http_traffic_body_type",
                table: "tunnel_http_traffic_exchange",
                column: "response_body_type");

            migrationBuilder.CreateIndex(
                name: "idx_http_traffic_captured_at",
                table: "tunnel_http_traffic_exchange",
                column: "captured_at");

            migrationBuilder.CreateIndex(
                name: "idx_http_traffic_client",
                table: "tunnel_http_traffic_exchange",
                column: "client_id");

            migrationBuilder.CreateIndex(
                name: "idx_http_traffic_route",
                table: "tunnel_http_traffic_exchange",
                column: "route");

            migrationBuilder.CreateIndex(
                name: "idx_http_traffic_tenant",
                table: "tunnel_http_traffic_exchange",
                column: "tenant_id");

            migrationBuilder.CreateIndex(
                name: "idx_management_user_role",
                table: "tunnel_management_user",
                column: "role");

            migrationBuilder.CreateIndex(
                name: "idx_management_user_tenant",
                table: "tunnel_management_user",
                column: "tenant_id");

            migrationBuilder.CreateIndex(
                name: "idx_resource_traffic_client",
                table: "tunnel_resource_traffic_usage",
                column: "client_id");

            migrationBuilder.CreateIndex(
                name: "idx_resource_traffic_date",
                table: "tunnel_resource_traffic_usage",
                column: "usage_date");

            migrationBuilder.CreateIndex(
                name: "idx_resource_traffic_tenant",
                table: "tunnel_resource_traffic_usage",
                column: "tenant_id");

            migrationBuilder.CreateIndex(
                name: "idx_resource_traffic_type",
                table: "tunnel_resource_traffic_usage",
                column: "resource_type");

            migrationBuilder.CreateIndex(
                name: "uk_resource_traffic_resource_date",
                table: "tunnel_resource_traffic_usage",
                columns: new[] { "tenant_id", "client_id", "resource_type", "resource_key", "usage_date" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "idx_tcp_traffic_channel",
                table: "tunnel_tcp_traffic_frame",
                column: "channel_id");

            migrationBuilder.CreateIndex(
                name: "idx_tcp_traffic_client",
                table: "tunnel_tcp_traffic_frame",
                column: "client_id");

            migrationBuilder.CreateIndex(
                name: "idx_tcp_traffic_frame_time",
                table: "tunnel_tcp_traffic_frame",
                column: "frame_time");

            migrationBuilder.CreateIndex(
                name: "idx_tcp_traffic_listen_port",
                table: "tunnel_tcp_traffic_frame",
                column: "listen_port");

            migrationBuilder.CreateIndex(
                name: "idx_tcp_traffic_stream",
                table: "tunnel_tcp_traffic_frame",
                columns: new[] { "tenant_id", "channel_id", "frame_direction", "stream_offset" });

            migrationBuilder.CreateIndex(
                name: "idx_tcp_traffic_tenant",
                table: "tunnel_tcp_traffic_frame",
                column: "tenant_id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "tunnel_http_traffic_exchange");

            migrationBuilder.DropTable(
                name: "tunnel_management_user");

            migrationBuilder.DropTable(
                name: "tunnel_resource_traffic_usage");

            migrationBuilder.DropTable(
                name: "tunnel_tcp_traffic_frame");

            migrationBuilder.DropColumn(
                name: "detail_capture_enabled",
                table: "tunnel_mapping");

            migrationBuilder.DropColumn(
                name: "detail_capture_enabled",
                table: "http_route_mapping");

            migrationBuilder.DropColumn(
                name: "path_rewrite_enabled",
                table: "http_route_mapping");
        }
    }
}
