using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ShuaiTunnel.Server.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddManagementRegistration : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "tunnel_management_registration_challenge",
                columns: table => new
                {
                    registration_id = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    username = table.Column<string>(type: "TEXT", maxLength: 80, nullable: false),
                    email = table.Column<string>(type: "TEXT", maxLength: 254, nullable: false),
                    password_hash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    code_hash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    attempts_remaining = table.Column<int>(type: "INTEGER", nullable: false),
                    expires_at = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    resend_available_at = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    created_at = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    updated_at = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tunnel_management_registration_challenge", x => x.registration_id);
                });

            migrationBuilder.CreateTable(
                name: "tunnel_management_user_email",
                columns: table => new
                {
                    username = table.Column<string>(type: "TEXT", maxLength: 80, nullable: false),
                    email = table.Column<string>(type: "TEXT", maxLength: 254, nullable: false),
                    verified_at = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    created_at = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    updated_at = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tunnel_management_user_email", x => x.username);
                });

            migrationBuilder.CreateIndex(
                name: "idx_registration_challenge_expiry",
                table: "tunnel_management_registration_challenge",
                column: "expires_at");

            migrationBuilder.CreateIndex(
                name: "uq_registration_challenge_email",
                table: "tunnel_management_registration_challenge",
                column: "email",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "uq_registration_challenge_username",
                table: "tunnel_management_registration_challenge",
                column: "username",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "idx_management_user_email_verified",
                table: "tunnel_management_user_email",
                column: "verified_at");

            migrationBuilder.CreateIndex(
                name: "uq_management_user_email",
                table: "tunnel_management_user_email",
                column: "email",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "tunnel_management_registration_challenge");

            migrationBuilder.DropTable(
                name: "tunnel_management_user_email");
        }
    }
}
