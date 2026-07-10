using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ShuaiTunnel.Server.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddPeerMeshAclDirection : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "direction",
                table: "peer_mesh_acl",
                type: "TEXT",
                maxLength: 16,
                nullable: false,
                defaultValue: "OUTBOUND");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "direction",
                table: "peer_mesh_acl");
        }
    }
}
