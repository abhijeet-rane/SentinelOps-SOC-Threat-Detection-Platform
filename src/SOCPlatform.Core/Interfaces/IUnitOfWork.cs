namespace SOCPlatform.Core.Interfaces;

/// <summary>
/// Unit of Work pattern for coordinating multiple repository operations in a single transaction.
/// </summary>
public interface IUnitOfWork : IDisposable
{
    IRepository<T> Repository<T>() where T : class;
    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
    Task BeginTransactionAsync();
    Task CommitTransactionAsync();
    Task RollbackTransactionAsync();
}
