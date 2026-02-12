using System.IO;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SOCPlatform.Core.DTOs;

namespace SOCPlatform.DesktopAgent.Services;

/// <summary>
/// SQLite-based offline buffer for logs when the API server is unreachable.
/// Stores logs locally and flushes them when connectivity is restored.
/// </summary>
public class OfflineBufferService : IDisposable
{
    private readonly string _dbPath;
    private readonly SqliteConnection _connection;

    public OfflineBufferService()
    {
        var appData = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SOCPlatform", "Agent");
        Directory.CreateDirectory(appData);

        _dbPath = Path.Combine(appData, "offline_buffer.db");
        _connection = new SqliteConnection($"Data Source={_dbPath}");
        _connection.Open();

        InitializeSchema();
    }

    private void InitializeSchema()
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS BufferedLogs (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                Payload TEXT NOT NULL,
                CreatedAt TEXT NOT NULL DEFAULT (datetime('now')),
                RetryCount INTEGER NOT NULL DEFAULT 0
            );
            """;
        cmd.ExecuteNonQuery();
    }

    /// <summary>
    /// Store a batch of logs in the local buffer for later upload.
    /// </summary>
    public void BufferLogs(List<LogIngestionDto> logs, Guid endpointId)
    {
        var batch = new BatchLogIngestionDto
        {
            EndpointId = endpointId,
            AgentVersion = "1.0.0",
            Logs = logs
        };

        var payload = JsonSerializer.Serialize(batch);

        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "INSERT INTO BufferedLogs (Payload) VALUES ($payload)";
        cmd.Parameters.AddWithValue("$payload", payload);
        cmd.ExecuteNonQuery();
    }

    /// <summary>
    /// Retrieve all buffered log batches for upload.
    /// </summary>
    public List<(long Id, string Payload)> GetBufferedLogs(int limit = 50)
    {
        var results = new List<(long Id, string Payload)>();

        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT Id, Payload FROM BufferedLogs ORDER BY Id LIMIT $limit";
        cmd.Parameters.AddWithValue("$limit", limit);

        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            results.Add((reader.GetInt64(0), reader.GetString(1)));
        }

        return results;
    }

    /// <summary>
    /// Remove successfully uploaded logs from the buffer.
    /// </summary>
    public void RemoveBufferedLogs(IEnumerable<long> ids)
    {
        using var transaction = _connection.BeginTransaction();
        using var cmd = _connection.CreateCommand();
        cmd.Transaction = transaction;

        foreach (var id in ids)
        {
            cmd.CommandText = "DELETE FROM BufferedLogs WHERE Id = $id";
            cmd.Parameters.Clear();
            cmd.Parameters.AddWithValue("$id", id);
            cmd.ExecuteNonQuery();
        }

        transaction.Commit();
    }

    /// <summary>
    /// Get the count of buffered logs.
    /// </summary>
    public int GetBufferedCount()
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM BufferedLogs";
        return Convert.ToInt32(cmd.ExecuteScalar());
    }

    public void Dispose()
    {
        _connection?.Dispose();
        GC.SuppressFinalize(this);
    }
}
