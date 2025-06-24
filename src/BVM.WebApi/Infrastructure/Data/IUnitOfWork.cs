namespace BVM.WebApi.Infrastructure.Data
{
    public interface IUnitOfWork
    {
        Task<int> CommitAsync(CancellationToken cancellationToken = default);
        IRepository<TEntity> GetRepository<TEntity>() where TEntity : class;
    }
}
