using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Specus.Server.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddPeerMeshNatBehavior : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "nat_behavior_discovery",
                table: "peer_mesh_device",
                type: "TEXT",
                maxLength: 40,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "nat_filtering_behavior",
                table: "peer_mesh_device",
                type: "TEXT",
                maxLength: 80,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "nat_mapping_behavior",
                table: "peer_mesh_device",
                type: "TEXT",
                maxLength: 80,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "nat_behavior_discovery",
                table: "peer_mesh_device");

            migrationBuilder.DropColumn(
                name: "nat_filtering_behavior",
                table: "peer_mesh_device");

            migrationBuilder.DropColumn(
                name: "nat_mapping_behavior",
                table: "peer_mesh_device");
        }
    }
}
