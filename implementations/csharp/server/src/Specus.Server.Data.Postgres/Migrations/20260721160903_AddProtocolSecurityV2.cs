using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Specus.Server.Data.Postgres.Migrations
{
    /// <inheritdoc />
    public partial class AddProtocolSecurityV2 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "specus_client_auth_nonce",
                columns: table => new
                {
                    api_key_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    nonce_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    expires_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    created_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_specus_client_auth_nonce", x => new { x.api_key_hash, x.nonce_hash });
                });

            migrationBuilder.CreateTable(
                name: "specus_websocket_ticket",
                columns: table => new
                {
                    token_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    scope = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    username = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true),
                    tenant_id = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true),
                    is_admin = table.Column<bool>(type: "boolean", nullable: false),
                    room_id = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: true),
                    room_key = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true),
                    peer_id = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: true),
                    display_name = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: true),
                    shared_room = table.Column<bool>(type: "boolean", nullable: false),
                    remote_address_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    created_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    expires_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_specus_websocket_ticket", x => x.token_hash);
                });

            migrationBuilder.CreateIndex(
                name: "idx_client_auth_nonce_expiry",
                table: "specus_client_auth_nonce",
                column: "expires_at");

            migrationBuilder.CreateIndex(
                name: "idx_websocket_ticket_expiry",
                table: "specus_websocket_ticket",
                column: "expires_at");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "specus_client_auth_nonce");

            migrationBuilder.DropTable(
                name: "specus_websocket_ticket");
        }
    }
}
