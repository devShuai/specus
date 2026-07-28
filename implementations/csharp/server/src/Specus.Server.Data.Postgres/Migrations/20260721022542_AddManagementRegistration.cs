using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Specus.Server.Data.Postgres.Migrations
{
    /// <inheritdoc />
    public partial class AddManagementRegistration : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "specus_management_registration_challenge",
                columns: table => new
                {
                    registration_id = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    username = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: false),
                    email = table.Column<string>(type: "character varying(254)", maxLength: 254, nullable: false),
                    password_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    code_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    attempts_remaining = table.Column<int>(type: "integer", nullable: false),
                    expires_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    resend_available_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    created_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    updated_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_specus_management_registration_challenge", x => x.registration_id);
                });

            migrationBuilder.CreateTable(
                name: "specus_management_user_email",
                columns: table => new
                {
                    username = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: false),
                    email = table.Column<string>(type: "character varying(254)", maxLength: 254, nullable: false),
                    verified_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    created_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    updated_at = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_specus_management_user_email", x => x.username);
                });

            migrationBuilder.CreateIndex(
                name: "idx_registration_challenge_expiry",
                table: "specus_management_registration_challenge",
                column: "expires_at");

            migrationBuilder.CreateIndex(
                name: "uq_registration_challenge_email",
                table: "specus_management_registration_challenge",
                column: "email",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "uq_registration_challenge_username",
                table: "specus_management_registration_challenge",
                column: "username",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "idx_management_user_email_verified",
                table: "specus_management_user_email",
                column: "verified_at");

            migrationBuilder.CreateIndex(
                name: "uq_management_user_email",
                table: "specus_management_user_email",
                column: "email",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "specus_management_registration_challenge");

            migrationBuilder.DropTable(
                name: "specus_management_user_email");
        }
    }
}
