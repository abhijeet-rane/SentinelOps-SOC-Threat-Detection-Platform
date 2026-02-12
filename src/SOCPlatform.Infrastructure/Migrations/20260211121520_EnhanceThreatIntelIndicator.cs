using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SOCPlatform.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class EnhanceThreatIntelIndicator : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ASN",
                table: "ThreatIntelIndicators",
                type: "character varying(200)",
                maxLength: 200,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "AssociatedCVEs",
                table: "ThreatIntelIndicators",
                type: "character varying(500)",
                maxLength: 500,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "ConfidenceScore",
                table: "ThreatIntelIndicators",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTime>(
                name: "FirstSeenAt",
                table: "ThreatIntelIndicators",
                type: "timestamp with time zone",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AddColumn<string>(
                name: "GeoCountry",
                table: "ThreatIntelIndicators",
                type: "character varying(100)",
                maxLength: 100,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "HitCount",
                table: "ThreatIntelIndicators",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTime>(
                name: "LastMatchedAt",
                table: "ThreatIntelIndicators",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "MitreTechniques",
                table: "ThreatIntelIndicators",
                type: "character varying(200)",
                maxLength: 200,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ThreatType",
                table: "ThreatIntelIndicators",
                type: "character varying(100)",
                maxLength: 100,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<DateTime>(
                name: "UpdatedAt",
                table: "ThreatIntelIndicators",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_ThreatIntelIndicators_IsActive",
                table: "ThreatIntelIndicators",
                column: "IsActive");

            migrationBuilder.CreateIndex(
                name: "IX_ThreatIntelIndicators_ThreatLevel",
                table: "ThreatIntelIndicators",
                column: "ThreatLevel");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_ThreatIntelIndicators_IsActive",
                table: "ThreatIntelIndicators");

            migrationBuilder.DropIndex(
                name: "IX_ThreatIntelIndicators_ThreatLevel",
                table: "ThreatIntelIndicators");

            migrationBuilder.DropColumn(
                name: "ASN",
                table: "ThreatIntelIndicators");

            migrationBuilder.DropColumn(
                name: "AssociatedCVEs",
                table: "ThreatIntelIndicators");

            migrationBuilder.DropColumn(
                name: "ConfidenceScore",
                table: "ThreatIntelIndicators");

            migrationBuilder.DropColumn(
                name: "FirstSeenAt",
                table: "ThreatIntelIndicators");

            migrationBuilder.DropColumn(
                name: "GeoCountry",
                table: "ThreatIntelIndicators");

            migrationBuilder.DropColumn(
                name: "HitCount",
                table: "ThreatIntelIndicators");

            migrationBuilder.DropColumn(
                name: "LastMatchedAt",
                table: "ThreatIntelIndicators");

            migrationBuilder.DropColumn(
                name: "MitreTechniques",
                table: "ThreatIntelIndicators");

            migrationBuilder.DropColumn(
                name: "ThreatType",
                table: "ThreatIntelIndicators");

            migrationBuilder.DropColumn(
                name: "UpdatedAt",
                table: "ThreatIntelIndicators");
        }
    }
}
