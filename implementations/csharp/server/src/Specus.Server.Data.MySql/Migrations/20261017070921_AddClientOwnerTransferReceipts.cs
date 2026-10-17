using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Specus.Server.Data.MySql.Migrations
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
                    id = table.Column<string>(type: "varchar(80)", maxLength: 80, nullable: false),
                    node_id = table.Column<string>(type: "varchar(32)", maxLength: 32, nullable: false),
                    event_id = table.Column<long>(type: "bigint", nullable: false),
                    processed_at = table.Column<string>(type: "varchar(40)", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_client_owner_transfer_receipt", x => x.id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

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
