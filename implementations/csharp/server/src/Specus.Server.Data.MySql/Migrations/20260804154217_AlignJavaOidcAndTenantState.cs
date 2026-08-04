using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Specus.Server.Data.MySql.Migrations
{
    /// <inheritdoc />
    public partial class AlignJavaOidcAndTenantState : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameIndex(
                name: "IX_specus_mapping_listen_port",
                table: "specus_mapping",
                newName: "uk_specus_mapping_listen_port");

            migrationBuilder.RenameIndex(
                name: "IX_specus_mapping_client_id",
                table: "specus_mapping",
                newName: "idx_specus_mapping_client");

            migrationBuilder.RenameIndex(
                name: "IX_http_route_mapping_client_id_route",
                table: "http_route_mapping",
                newName: "uk_http_route_client_route");

            migrationBuilder.RenameIndex(
                name: "IX_http_route_mapping_client_id",
                table: "http_route_mapping",
                newName: "idx_http_route_client");

            migrationBuilder.AddColumn<string>(
                name: "tenant_id",
                table: "specus_mapping",
                type: "varchar(80)",
                maxLength: 80,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "oidc_identity_key",
                table: "specus_management_user",
                type: "varchar(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "oidc_issuer",
                table: "specus_management_user",
                type: "varchar(255)",
                maxLength: 255,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "oidc_subject",
                table: "specus_management_user",
                type: "varchar(255)",
                maxLength: 255,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "last_keepalive_at",
                table: "peer_mesh_session",
                type: "varchar(40)",
                maxLength: 40,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "tenant_id",
                table: "http_route_mapping",
                type: "varchar(80)",
                maxLength: 80,
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "idx_specus_mapping_tenant",
                table: "specus_mapping",
                column: "tenant_id");

            migrationBuilder.CreateIndex(
                name: "idx_specus_mapping_tenant_client_enabled_id",
                table: "specus_mapping",
                columns: new[] { "tenant_id", "client_id", "enabled", "Id" });

            migrationBuilder.CreateIndex(
                name: "idx_specus_mapping_tenant_client_id",
                table: "specus_mapping",
                columns: new[] { "tenant_id", "client_id", "Id" });

            migrationBuilder.CreateIndex(
                name: "uq_management_user_oidc_identity_key",
                table: "specus_management_user",
                column: "oidc_identity_key",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "idx_http_route_tenant",
                table: "http_route_mapping",
                column: "tenant_id");

            migrationBuilder.CreateIndex(
                name: "idx_http_route_tenant_client_enabled_id",
                table: "http_route_mapping",
                columns: new[] { "tenant_id", "client_id", "enabled", "Id" });

            migrationBuilder.CreateIndex(
                name: "idx_http_route_tenant_client_id",
                table: "http_route_mapping",
                columns: new[] { "tenant_id", "client_id", "Id" });

            migrationBuilder.CreateIndex(
                name: "idx_http_route_tenant_client_route",
                table: "http_route_mapping",
                columns: new[] { "tenant_id", "client_id", "route" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "idx_specus_mapping_tenant",
                table: "specus_mapping");

            migrationBuilder.DropIndex(
                name: "idx_specus_mapping_tenant_client_enabled_id",
                table: "specus_mapping");

            migrationBuilder.DropIndex(
                name: "idx_specus_mapping_tenant_client_id",
                table: "specus_mapping");

            migrationBuilder.DropIndex(
                name: "uq_management_user_oidc_identity_key",
                table: "specus_management_user");

            migrationBuilder.DropIndex(
                name: "idx_http_route_tenant",
                table: "http_route_mapping");

            migrationBuilder.DropIndex(
                name: "idx_http_route_tenant_client_enabled_id",
                table: "http_route_mapping");

            migrationBuilder.DropIndex(
                name: "idx_http_route_tenant_client_id",
                table: "http_route_mapping");

            migrationBuilder.DropIndex(
                name: "idx_http_route_tenant_client_route",
                table: "http_route_mapping");

            migrationBuilder.DropColumn(
                name: "tenant_id",
                table: "specus_mapping");

            migrationBuilder.DropColumn(
                name: "oidc_identity_key",
                table: "specus_management_user");

            migrationBuilder.DropColumn(
                name: "oidc_issuer",
                table: "specus_management_user");

            migrationBuilder.DropColumn(
                name: "oidc_subject",
                table: "specus_management_user");

            migrationBuilder.DropColumn(
                name: "last_keepalive_at",
                table: "peer_mesh_session");

            migrationBuilder.DropColumn(
                name: "tenant_id",
                table: "http_route_mapping");

            migrationBuilder.RenameIndex(
                name: "uk_specus_mapping_listen_port",
                table: "specus_mapping",
                newName: "IX_specus_mapping_listen_port");

            migrationBuilder.RenameIndex(
                name: "idx_specus_mapping_client",
                table: "specus_mapping",
                newName: "IX_specus_mapping_client_id");

            migrationBuilder.RenameIndex(
                name: "uk_http_route_client_route",
                table: "http_route_mapping",
                newName: "IX_http_route_mapping_client_id_route");

            migrationBuilder.RenameIndex(
                name: "idx_http_route_client",
                table: "http_route_mapping",
                newName: "IX_http_route_mapping_client_id");
        }
    }
}
