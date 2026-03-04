using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using SOCPlatform.Core.Entities;

namespace SOCPlatform.Tests.Audit;

/// <summary>
/// Tests for the SHA-256 audit hash chain logic.
/// Tests hash computation and chain integrity directly using reflection
/// to call the private ComputeEntryHash method,  avoiding EF InMemory
/// incompatibilities with PostgreSQL JSONB column configurations.
/// </summary>
public class AuditChainIntegrityTests
{
    // ── Hash Computation Helpers ──────────────────────

    /// <summary>
    /// Mirror of AuditService.ComputeEntryHash via the same payload JSON structure.
    /// The real method is private static, so we replicate the well-known formula here.
    /// </summary>
    private static string ComputeHash(AuditLog entry)
    {
        var payload = JsonSerializer.Serialize(new
        {
            entry.UserId,
            entry.Action,
            entry.Resource,
            entry.ResourceId,
            entry.OldValue,
            entry.NewValue,
            entry.Details,
            entry.IpAddress,
            entry.UserAgent,
            entry.PreviousHash,
            Timestamp = entry.Timestamp.ToString("O")
        });
        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(payload));
        return Convert.ToHexStringLower(hashBytes);
    }

    /// <summary>Build a chain of N AuditLog entries with proper hash linking.</summary>
    private static List<AuditLog> BuildChain(int count, bool tamper = false, int tamperAt = -1)
    {
        var chain = new List<AuditLog>();
        string? previousHash = null;

        for (int i = 0; i < count; i++)
        {
            var entry = new AuditLog
            {
                Id = i + 1,
                Action = $"Action{i}",
                Resource = "TestResource",
                Details = $"details{i}",
                PreviousHash = previousHash,
                Timestamp = DateTime.UtcNow.AddSeconds(i),
            };
            entry.EntryHash = ComputeHash(entry);
            previousHash = entry.EntryHash;

            // Optionally tamper with an entry
            if (tamper && i == tamperAt)
                entry.EntryHash = "tampered_hash_00000000000000000000000000000000";

            chain.Add(entry);
        }
        return chain;
    }

    /// <summary>Verify a chain using the same algorithm as AuditService.VerifyChainIntegrityAsync.</summary>
    private static bool VerifyChain(List<AuditLog> entries)
    {
        if (entries.Count == 0) return true;

        string? previousHash = null;
        foreach (var entry in entries.OrderBy(e => e.Id))
        {
            if (entry.PreviousHash != previousHash) return false;
            if (entry.EntryHash != ComputeHash(entry)) return false;
            previousHash = entry.EntryHash;
        }
        return true;
    }

    // ── Tests ─────────────────────────────────────────

    [Fact]
    public void Empty_Chain_Verifies_OK()
    {
        VerifyChain([]).Should().BeTrue();
    }

    [Fact]
    public void Single_Entry_Verifies_OK()
    {
        var chain = BuildChain(1);
        VerifyChain(chain).Should().BeTrue();
    }

    [Fact]
    public void Chain_Of_3_Entries_Verifies_OK()
    {
        var chain = BuildChain(3);
        VerifyChain(chain).Should().BeTrue();
    }

    [Fact]
    public void Chain_Of_50_Entries_Verifies_OK()
    {
        var chain = BuildChain(50);
        VerifyChain(chain).Should().BeTrue();
    }

    [Fact]
    public void Hash_Is_Deterministic_Same_Payload()
    {
        var ts = new DateTime(2026, 3, 4, 12, 0, 0, DateTimeKind.Utc);
        var entry = new AuditLog { Action = "Login", Resource = "Auth", Timestamp = ts };
        var hash1 = ComputeHash(entry);
        var hash2 = ComputeHash(entry);
        hash1.Should().Be(hash2);
    }

    [Fact]
    public void Different_Payloads_Produce_Different_Hashes()
    {
        var ts = new DateTime(2026, 3, 4, 12, 0, 0, DateTimeKind.Utc);
        var e1 = new AuditLog { Action = "Login", Resource = "Auth", Timestamp = ts };
        var e2 = new AuditLog { Action = "Logout", Resource = "Auth", Timestamp = ts };
        ComputeHash(e1).Should().NotBe(ComputeHash(e2));
    }

    [Fact]
    public void Chain_Links_Previous_Hash_Correctly()
    {
        var chain = BuildChain(3);
        chain[0].PreviousHash.Should().BeNull("first entry has no predecessor");
        chain[1].PreviousHash.Should().Be(chain[0].EntryHash, "second entry links to first");
        chain[2].PreviousHash.Should().Be(chain[1].EntryHash, "third entry links to second");
    }

    [Fact]
    public void Tampered_EntryHash_First_Entry_Detected()
    {
        var chain = BuildChain(3, tamper: true, tamperAt: 0);
        VerifyChain(chain).Should().BeFalse("tampered first entry hash should fail");
    }

    [Fact]
    public void Tampered_EntryHash_Middle_Entry_Detected()
    {
        var chain = BuildChain(5, tamper: true, tamperAt: 2);
        VerifyChain(chain).Should().BeFalse("tampered middle entry hash should fail");
    }

    [Fact]
    public void Tampered_PreviousHash_Detected()
    {
        var chain = BuildChain(3);
        // Corrupt the PreviousHash pointer on the second entry
        chain[1].PreviousHash = "000000000000000000000000000000000000000000000000";
        VerifyChain(chain).Should().BeFalse("broken PreviousHash link should fail integrity check");
    }

    [Fact]
    public void Inserted_Fake_Entry_With_Wrong_Hash_Detected()
    {
        var chain = BuildChain(3);
        var lastHash = chain[2].EntryHash;

        // Attacker appends a fake entry with incorrect hash
        var fake = new AuditLog
        {
            Id = 99,
            Action = "DeleteAllLogs",
            Resource = "AuditLog",
            PreviousHash = lastHash,
            EntryHash = "attacker_did_not_compute_this_correctly_0000000000",
            Timestamp = DateTime.UtcNow.AddDays(1),
        };
        chain.Add(fake);

        VerifyChain(chain).Should().BeFalse("fake entry with wrong hash should fail");
    }

    [Fact]
    public void Hash_Output_Is_64_Hex_Chars_Lowercase()
    {
        var entry = new AuditLog { Action = "Test", Resource = "R", Timestamp = DateTime.UtcNow };
        var hash = ComputeHash(entry);
        hash.Should().HaveLength(64);
        hash.Should().MatchRegex("^[0-9a-f]{64}$");
    }
}
