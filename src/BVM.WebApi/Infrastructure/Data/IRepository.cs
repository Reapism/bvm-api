using Sweaj.Patterns.Data.Entities;

namespace BVM.WebApi.Infrastructure.Data
{
    public interface IRepository<TEntity>
         where TEntity : class
    {
        IQueryable<TEntity> Query();

        Task AddAsync(TEntity entity, CancellationToken cancellationToken);

        Task AddRangeAsync(IEnumerable<TEntity> entities, CancellationToken cancellationToken);

        Task DeleteAsync(TEntity entity);

        Task UpdateAsync(TEntity entity);
    }
}
