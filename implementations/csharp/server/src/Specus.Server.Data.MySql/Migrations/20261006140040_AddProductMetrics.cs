using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Specus.Server.Data.MySql.Migrations
{
    /// <inheritdoc />
    public partial class AddProductMetrics : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "product_metrics_onboarding_daily",
                columns: table => new
                {
                    tenant_id = table.Column<string>(type: "varchar(80)", maxLength: 80, nullable: false),
                    cohort_day = table.Column<string>(type: "varchar(10)", maxLength: 10, nullable: false),
                    reached_step = table.Column<string>(type: "varchar(32)", maxLength: 32, nullable: false),
                    duration_bucket = table.Column<string>(type: "varchar(16)", maxLength: 16, nullable: false),
                    users = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_product_metrics_onboarding_daily", x => new { x.tenant_id, x.cohort_day, x.reached_step, x.duration_bucket });
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "product_metrics_onboarding_progress",
                columns: table => new
                {
                    tenant_id = table.Column<string>(type: "varchar(80)", maxLength: 80, nullable: false),
                    username = table.Column<string>(type: "varchar(80)", maxLength: 80, nullable: false),
                    started_at = table.Column<long>(type: "bigint", nullable: false),
                    signed_in_at = table.Column<long>(type: "bigint", nullable: true),
                    credential_created_at = table.Column<long>(type: "bigint", nullable: true),
                    client_online_at = table.Column<long>(type: "bigint", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_product_metrics_onboarding_progress", x => new { x.tenant_id, x.username });
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "product_metrics_switch",
                columns: table => new
                {
                    tenant_id = table.Column<string>(type: "varchar(80)", maxLength: 80, nullable: false),
                    enabled = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    updated_by = table.Column<string>(type: "varchar(80)", maxLength: 80, nullable: true),
                    updated_at = table.Column<long>(type: "bigint", nullable: true),
                    purged_at = table.Column<long>(type: "bigint", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_product_metrics_switch", x => x.tenant_id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "product_metrics_transfer_daily",
                columns: table => new
                {
                    tenant_id = table.Column<string>(type: "varchar(80)", maxLength: 80, nullable: false),
                    day = table.Column<string>(type: "varchar(10)", maxLength: 10, nullable: false),
                    mode = table.Column<string>(type: "varchar(16)", maxLength: 16, nullable: false),
                    path = table.Column<string>(type: "varchar(16)", maxLength: 16, nullable: false),
                    size_bucket = table.Column<string>(type: "varchar(16)", maxLength: 16, nullable: false),
                    attempt = table.Column<string>(type: "varchar(32)", maxLength: 32, nullable: false),
                    outcome = table.Column<string>(type: "varchar(16)", maxLength: 16, nullable: false),
                    count = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_product_metrics_transfer_daily", x => new { x.tenant_id, x.day, x.mode, x.path, x.size_bucket, x.attempt, x.outcome });
                })
                .Annotation("MySQL:Charset", "utf8mb4");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "product_metrics_onboarding_daily");

            migrationBuilder.DropTable(
                name: "product_metrics_onboarding_progress");

            migrationBuilder.DropTable(
                name: "product_metrics_switch");

            migrationBuilder.DropTable(
                name: "product_metrics_transfer_daily");
        }
    }
}
