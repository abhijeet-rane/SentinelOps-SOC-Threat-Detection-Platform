using System.ComponentModel.DataAnnotations;

namespace SOCPlatform.Infrastructure.Configuration;

public sealed class RedisOptions
{
    public const string SectionName = "Redis";

    [Required] public string Host { get; init; } = "localhost";
    [Range(1, 65535)] public int Port { get; init; } = 6379;
    public string? Password { get; init; }
    public int Database { get; init; } = 0;
    public string InstanceName { get; init; } = "socplatform:";

    public string ConnectionString =>
        string.IsNullOrEmpty(Password)
            ? $"{Host}:{Port},defaultDatabase={Database}"
            : $"{Host}:{Port},password={Password},defaultDatabase={Database}";
}
