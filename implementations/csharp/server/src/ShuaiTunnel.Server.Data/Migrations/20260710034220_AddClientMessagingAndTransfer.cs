using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ShuaiTunnel.Server.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddClientMessagingAndTransfer : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "message_attachments_capable",
                table: "tunnel_client_session",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<long>(
                name: "message_max_attachment_bytes",
                table: "tunnel_client_session",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0L);

            migrationBuilder.AddColumn<bool>(
                name: "message_media_preview_capable",
                table: "tunnel_client_session",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "message_receive_capable",
                table: "tunnel_client_session",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "message_send_capable",
                table: "tunnel_client_session",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

            migrationBuilder.CreateTable(
                name: "transfer_attachment",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false),
                    tenant_id = table.Column<string>(type: "TEXT", maxLength: 80, nullable: true),
                    scope = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    room_id = table.Column<string>(type: "TEXT", maxLength: 120, nullable: true),
                    room_token_hash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    owner_username = table.Column<string>(type: "TEXT", maxLength: 80, nullable: true),
                    target_client_id = table.Column<long>(type: "INTEGER", nullable: true),
                    object_key = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    file_name = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    mime_type = table.Column<string>(type: "TEXT", maxLength: 120, nullable: false),
                    size_bytes = table.Column<long>(type: "INTEGER", nullable: false),
                    sha256 = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    status = table.Column<string>(type: "TEXT", maxLength: 24, nullable: false),
                    created_at = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    updated_at = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    upload_expires_at = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    expires_at = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    uploaded_at = table.Column<string>(type: "TEXT", maxLength: 40, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_transfer_attachment", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "idx_transfer_attachment_expires",
                table: "transfer_attachment",
                columns: new[] { "expires_at", "status" });

            migrationBuilder.CreateIndex(
                name: "idx_transfer_attachment_room",
                table: "transfer_attachment",
                columns: new[] { "scope", "room_id", "id" });

            migrationBuilder.CreateIndex(
                name: "idx_transfer_attachment_tenant",
                table: "transfer_attachment",
                columns: new[] { "tenant_id", "scope", "id" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "transfer_attachment");

            migrationBuilder.DropColumn(
                name: "message_attachments_capable",
                table: "tunnel_client_session");

            migrationBuilder.DropColumn(
                name: "message_max_attachment_bytes",
                table: "tunnel_client_session");

            migrationBuilder.DropColumn(
                name: "message_media_preview_capable",
                table: "tunnel_client_session");

            migrationBuilder.DropColumn(
                name: "message_receive_capable",
                table: "tunnel_client_session");

            migrationBuilder.DropColumn(
                name: "message_send_capable",
                table: "tunnel_client_session");
        }
    }
}
