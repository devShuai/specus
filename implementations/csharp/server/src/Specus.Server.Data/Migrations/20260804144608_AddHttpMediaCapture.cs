using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Specus.Server.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddHttpMediaCapture : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "media_capture_enabled",
                table: "http_route_mapping",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

            migrationBuilder.CreateTable(
                name: "specus_http_media_capture",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    tenant_id = table.Column<string>(type: "TEXT", maxLength: 80, nullable: false),
                    client_id = table.Column<long>(type: "INTEGER", nullable: false),
                    client_name = table.Column<string>(type: "TEXT", maxLength: 120, nullable: false),
                    route = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    resource_id = table.Column<long>(type: "INTEGER", nullable: true),
                    source_url = table.Column<string>(type: "TEXT", maxLength: 3072, nullable: false),
                    resource_key = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    deduplication_key = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    method = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    status_code = table.Column<int>(type: "INTEGER", nullable: false),
                    content_type = table.Column<string>(type: "TEXT", maxLength: 255, nullable: true),
                    content_encoding = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    media_kind = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    entity_tag = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
                    last_modified = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    content_range_start = table.Column<long>(type: "INTEGER", nullable: true),
                    content_range_end = table.Column<long>(type: "INTEGER", nullable: true),
                    total_bytes = table.Column<long>(type: "INTEGER", nullable: true),
                    captured_bytes = table.Column<long>(type: "INTEGER", nullable: false),
                    segment_sequence = table.Column<long>(type: "INTEGER", nullable: true),
                    initialization_segment = table.Column<bool>(type: "INTEGER", nullable: false),
                    live_stream = table.Column<bool>(type: "INTEGER", nullable: false),
                    object_key = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: false),
                    upload_id = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true),
                    object_etag = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
                    state = table.Column<string>(type: "TEXT", maxLength: 24, nullable: false),
                    failure_reason = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: true),
                    response_headers = table.Column<string>(type: "TEXT", nullable: true),
                    captured_at = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    completed_at = table.Column<string>(type: "TEXT", maxLength: 40, nullable: true),
                    expires_at = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_specus_http_media_capture", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "specus_http_media_reference",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    tenant_id = table.Column<string>(type: "TEXT", maxLength: 80, nullable: false),
                    manifest_capture_id = table.Column<long>(type: "INTEGER", nullable: false),
                    relation_type = table.Column<string>(type: "TEXT", maxLength: 24, nullable: false),
                    sequence_index = table.Column<long>(type: "INTEGER", nullable: true),
                    original_uri = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: false),
                    resolved_source_url = table.Column<string>(type: "TEXT", maxLength: 3072, nullable: false),
                    created_at = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_specus_http_media_reference", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "idx_http_media_state_expires",
                table: "specus_http_media_capture",
                columns: new[] { "state", "expires_at" });

            migrationBuilder.CreateIndex(
                name: "idx_http_media_tenant_client_id",
                table: "specus_http_media_capture",
                columns: new[] { "tenant_id", "client_id", "id" });

            migrationBuilder.CreateIndex(
                name: "idx_http_media_tenant_client_route_id",
                table: "specus_http_media_capture",
                columns: new[] { "tenant_id", "client_id", "route", "id" });

            migrationBuilder.CreateIndex(
                name: "idx_http_media_tenant_id",
                table: "specus_http_media_capture",
                columns: new[] { "tenant_id", "id" });

            migrationBuilder.CreateIndex(
                name: "idx_http_media_tenant_resource_id",
                table: "specus_http_media_capture",
                columns: new[] { "tenant_id", "resource_key", "id" });

            migrationBuilder.CreateIndex(
                name: "uk_http_media_deduplication_key",
                table: "specus_http_media_capture",
                column: "deduplication_key",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "idx_http_media_reference_manifest",
                table: "specus_http_media_reference",
                columns: new[] { "tenant_id", "manifest_capture_id" });

            migrationBuilder.CreateIndex(
                name: "idx_http_media_reference_manifest_sequence",
                table: "specus_http_media_reference",
                columns: new[] { "tenant_id", "manifest_capture_id", "sequence_index" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "specus_http_media_capture");

            migrationBuilder.DropTable(
                name: "specus_http_media_reference");

            migrationBuilder.DropColumn(
                name: "media_capture_enabled",
                table: "http_route_mapping");
        }
    }
}
