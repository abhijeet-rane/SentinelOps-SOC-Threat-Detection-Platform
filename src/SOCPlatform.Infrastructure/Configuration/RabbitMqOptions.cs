using System.ComponentModel.DataAnnotations;

namespace SOCPlatform.Infrastructure.Configuration;

public sealed class RabbitMqOptions
{
    public const string SectionName = "RabbitMq";

    [Required] public string Host { get; init; } = "localhost";
    [Range(1, 65535)] public int Port { get; init; } = 5672;
    [Required] public string UserName { get; init; } = "guest";
    [Required] public string Password { get; init; } = "guest";
    public string VirtualHost { get; init; } = "/";

    public string LogIngestionExchange { get; init; } = "soc.logs";
    public string LogIngestionQueue { get; init; } = "soc.logs.ingest";
}
