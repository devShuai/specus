using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Specus.Server.Data.MySql.Migrations
{
    /// <inheritdoc />
    public partial class AddDiagramAndTransferRooms : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "public_transfer_diagram_version",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false),
                    room_id = table.Column<long>(type: "bigint", nullable: false),
                    name = table.Column<string>(type: "varchar(80)", maxLength: 80, nullable: false),
                    author_peer_id = table.Column<string>(type: "varchar(120)", maxLength: 120, nullable: false),
                    snapshot_data = table.Column<byte[]>(type: "longblob", nullable: false),
                    size_bytes = table.Column<long>(type: "bigint", nullable: false),
                    created_at = table.Column<string>(type: "varchar(40)", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_public_transfer_diagram_version", x => x.id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "public_transfer_room",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false),
                    room_name = table.Column<string>(type: "varchar(120)", maxLength: 120, nullable: false),
                    owner_token_hash = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false),
                    created_by_peer_id = table.Column<string>(type: "varchar(120)", maxLength: 120, nullable: false),
                    created_at = table.Column<string>(type: "varchar(40)", maxLength: 40, nullable: false),
                    updated_at = table.Column<string>(type: "varchar(40)", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_public_transfer_room", x => x.id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "public_transfer_room_access",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false),
                    room_id = table.Column<long>(type: "bigint", nullable: false),
                    token_hash = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false),
                    role = table.Column<string>(type: "varchar(16)", maxLength: 16, nullable: false),
                    label = table.Column<string>(type: "varchar(80)", maxLength: 80, nullable: false),
                    created_at = table.Column<string>(type: "varchar(40)", maxLength: 40, nullable: false),
                    expires_at = table.Column<string>(type: "varchar(40)", maxLength: 40, nullable: true),
                    revoked_at = table.Column<string>(type: "varchar(40)", maxLength: 40, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_public_transfer_room_access", x => x.id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "public_transfer_room_pairing_code",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false),
                    room_id = table.Column<long>(type: "bigint", nullable: false),
                    code_hash = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false),
                    role = table.Column<string>(type: "varchar(16)", maxLength: 16, nullable: false),
                    label = table.Column<string>(type: "varchar(80)", maxLength: 80, nullable: false),
                    created_at = table.Column<string>(type: "varchar(40)", maxLength: 40, nullable: false),
                    expires_at = table.Column<string>(type: "varchar(40)", maxLength: 40, nullable: false),
                    max_uses = table.Column<int>(type: "int", nullable: false),
                    used_count = table.Column<int>(type: "int", nullable: false),
                    revoked_at = table.Column<string>(type: "varchar(40)", maxLength: 40, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_public_transfer_room_pairing_code", x => x.id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "user_diagram_document",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false),
                    tenant_id = table.Column<string>(type: "varchar(80)", maxLength: 80, nullable: false),
                    owner_username = table.Column<string>(type: "varchar(160)", maxLength: 160, nullable: false),
                    name = table.Column<string>(type: "varchar(120)", maxLength: 120, nullable: false),
                    snapshot_data = table.Column<byte[]>(type: "longblob", nullable: false),
                    size_bytes = table.Column<long>(type: "bigint", nullable: false),
                    revision = table.Column<long>(type: "bigint", nullable: false, defaultValue: 0L),
                    created_at = table.Column<string>(type: "varchar(40)", maxLength: 40, nullable: false),
                    updated_at = table.Column<string>(type: "varchar(40)", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_user_diagram_document", x => x.id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateIndex(
                name: "idx_public_transfer_version_created",
                table: "public_transfer_diagram_version",
                column: "created_at");

            migrationBuilder.CreateIndex(
                name: "idx_public_transfer_version_room",
                table: "public_transfer_diagram_version",
                column: "room_id");

            migrationBuilder.CreateIndex(
                name: "idx_public_transfer_room_name",
                table: "public_transfer_room",
                column: "room_name");

            migrationBuilder.CreateIndex(
                name: "uk_public_transfer_room_key",
                table: "public_transfer_room",
                columns: new[] { "room_name", "owner_token_hash" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "idx_public_transfer_access_room",
                table: "public_transfer_room_access",
                column: "room_id");

            migrationBuilder.CreateIndex(
                name: "uk_public_transfer_access_token",
                table: "public_transfer_room_access",
                column: "token_hash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "idx_public_transfer_pairing_room",
                table: "public_transfer_room_pairing_code",
                column: "room_id");

            migrationBuilder.CreateIndex(
                name: "uk_public_transfer_pairing_code_hash",
                table: "public_transfer_room_pairing_code",
                column: "code_hash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "idx_user_diagram_owner",
                table: "user_diagram_document",
                columns: new[] { "tenant_id", "owner_username" });

            migrationBuilder.CreateIndex(
                name: "idx_user_diagram_updated",
                table: "user_diagram_document",
                column: "updated_at");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "public_transfer_diagram_version");

            migrationBuilder.DropTable(
                name: "public_transfer_room");

            migrationBuilder.DropTable(
                name: "public_transfer_room_access");

            migrationBuilder.DropTable(
                name: "public_transfer_room_pairing_code");

            migrationBuilder.DropTable(
                name: "user_diagram_document");
        }
    }
}
