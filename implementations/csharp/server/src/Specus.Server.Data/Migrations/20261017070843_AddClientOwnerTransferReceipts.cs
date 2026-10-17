using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Specus.Server.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddClientOwnerTransferReceipts : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "client_owner_transfer_receipt",
                columns: table => new
                {
                    id = table.Column<string>(type: "TEXT", maxLength: 80, nullable: false),
                    node_id = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    event_id = table.Column<long>(type: "INTEGER", nullable: false),
                    processed_at = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_client_owner_transfer_receipt", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "idx_owner_transfer_receipt_node_event",
                table: "client_owner_transfer_receipt",
                columns: new[] { "node_id", "event_id" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            throw new NotSupportedException("Downgrade would discard ownership convergence receipts; restore a verified backup instead.");
        }
    }
}
