using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Specus.Server.Data.MySql.Migrations
{
    /// <inheritdoc />
    public partial class AddPeerEgressSwitch : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "peer_mesh_egress_switch",
                columns: table => new
                {
                    tenant_id = table.Column<string>(type: "varchar(80)", maxLength: 80, nullable: false),
                    enabled = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    updated_by = table.Column<string>(type: "varchar(80)", maxLength: 80, nullable: true),
                    updated_at = table.Column<string>(type: "varchar(40)", maxLength: 40, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_peer_mesh_egress_switch", x => x.tenant_id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "peer_mesh_egress_switch");
        }
    }
}
