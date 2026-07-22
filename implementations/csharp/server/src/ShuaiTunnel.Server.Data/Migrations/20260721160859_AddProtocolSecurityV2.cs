using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ShuaiTunnel.Server.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddProtocolSecurityV2 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "tunnel_client_auth_nonce",
                columns: table => new
                {
                    api_key_hash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    nonce_hash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    expires_at = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    created_at = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tunnel_client_auth_nonce", x => new { x.api_key_hash, x.nonce_hash });
                });

            migrationBuilder.CreateTable(
                name: "tunnel_websocket_ticket",
                columns: table => new
                {
                    token_hash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    scope = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    username = table.Column<string>(type: "TEXT", maxLength: 80, nullable: true),
                    tenant_id = table.Column<string>(type: "TEXT", maxLength: 80, nullable: true),
                    is_admin = table.Column<bool>(type: "INTEGER", nullable: false),
                    room_id = table.Column<string>(type: "TEXT", maxLength: 120, nullable: true),
                    room_key = table.Column<string>(type: "TEXT", maxLength: 80, nullable: true),
                    peer_id = table.Column<string>(type: "TEXT", maxLength: 120, nullable: true),
                    display_name = table.Column<string>(type: "TEXT", maxLength: 120, nullable: true),
                    shared_room = table.Column<bool>(type: "INTEGER", nullable: false),
                    remote_address_hash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    created_at = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    expires_at = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tunnel_websocket_ticket", x => x.token_hash);
                });

            migrationBuilder.CreateIndex(
                name: "idx_client_auth_nonce_expiry",
                table: "tunnel_client_auth_nonce",
                column: "expires_at");

            migrationBuilder.CreateIndex(
                name: "idx_websocket_ticket_expiry",
                table: "tunnel_websocket_ticket",
                column: "expires_at");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "tunnel_client_auth_nonce");

            migrationBuilder.DropTable(
                name: "tunnel_websocket_ticket");
        }
    }
}
