using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Specus.Server.Data.Postgres.Migrations
{
    /// <inheritdoc />
    public partial class AddManagementLoginNames : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "login_name",
                table: "specus_management_user",
                type: "character varying(80)",
                maxLength: 80,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "login_name_normalized",
                table: "specus_management_user",
                type: "character varying(80)",
                maxLength: 80,
                nullable: true);

            // Accounts that predate login names keep their username (the account key) as their
            // login name, so every owner column that records it keeps pointing at the same account
            // (protocol/spec/management-accounts.md section 3). Both values are written from the
            // same expression so the result does not depend on the dialect's assignment order.
            // Two names in one tenant that differ only in case make the unique index below fail,
            // and with it the migration and the start.
            migrationBuilder.Sql("""
                UPDATE specus_management_user
                SET login_name = COALESCE(NULLIF(TRIM(login_name), ''), username),
                    login_name_normalized = LOWER(TRIM(COALESCE(NULLIF(TRIM(login_name), ''), username)));
                """);

            migrationBuilder.CreateIndex(
                name: "uq_management_user_tenant_login_name",
                table: "specus_management_user",
                columns: new[] { "tenant_id", "login_name_normalized" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "uq_management_user_tenant_login_name",
                table: "specus_management_user");

            migrationBuilder.DropColumn(
                name: "login_name",
                table: "specus_management_user");

            migrationBuilder.DropColumn(
                name: "login_name_normalized",
                table: "specus_management_user");
        }
    }
}
