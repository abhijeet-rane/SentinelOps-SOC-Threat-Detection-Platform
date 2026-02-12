using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SOCPlatform.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddApiKeySecurityFields : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "AllowedEndpoints",
                table: "ApiKeys",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "IsRevoked",
                table: "ApiKeys",
                type: "boolean",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AllowedEndpoints",
                table: "ApiKeys");

            migrationBuilder.DropColumn(
                name: "IsRevoked",
                table: "ApiKeys");
        }
    }
}
