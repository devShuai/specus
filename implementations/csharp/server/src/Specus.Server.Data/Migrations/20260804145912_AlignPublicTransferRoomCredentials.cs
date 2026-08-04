using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Specus.Server.Data.Migrations
{
    /// <inheritdoc />
    public partial class AlignPublicTransferRoomCredentials : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<long>(
                name: "public_transfer_room_id",
                table: "transfer_attachment",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "discoverable",
                table: "specus_websocket_ticket",
                type: "INTEGER",
                nullable: false,
                defaultValue: true);

            migrationBuilder.AddColumn<string>(
                name: "room_role",
                table: "specus_websocket_ticket",
                type: "TEXT",
                maxLength: 16,
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "idx_transfer_attachment_public_room",
                table: "transfer_attachment",
                columns: new[] { "scope", "public_transfer_room_id", "id" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "idx_transfer_attachment_public_room",
                table: "transfer_attachment");

            migrationBuilder.DropColumn(
                name: "public_transfer_room_id",
                table: "transfer_attachment");

            migrationBuilder.DropColumn(
                name: "discoverable",
                table: "specus_websocket_ticket");

            migrationBuilder.DropColumn(
                name: "room_role",
                table: "specus_websocket_ticket");
        }
    }
}
