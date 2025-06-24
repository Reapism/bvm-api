using Microsoft.EntityFrameworkCore;

namespace BVM.WebApi.Infrastructure.Data
{
    public class Repository<TEntity> : IRepository<TEntity>
        where TEntity : class
    {
        private readonly BvmDbContext bvmDbContext;

        public Repository(BvmDbContext bvmDbContext)
        {
            this.bvmDbContext = bvmDbContext;
        }
        public IQueryable<TEntity> Query()
        {
            return bvmDbContext.Set<TEntity>().AsNoTracking();
        }

        public async Task AddAsync(TEntity entity, CancellationToken cancellationToken)
        {
            await bvmDbContext.Set<TEntity>().AddAsync(entity, cancellationToken);
        }

        public async Task AddRangeAsync(IEnumerable<TEntity> entities, CancellationToken cancellationToken)
        {
            await bvmDbContext.Set<TEntity>().AddRangeAsync(entities, cancellationToken);
        }

        public Task DeleteAsync(TEntity entity)
        {
            bvmDbContext.Set<TEntity>().Remove(entity);
            return Task.CompletedTask;
        }

        public Task UpdateAsync(TEntity entity)
        {
            bvmDbContext.Set<TEntity>().Update(entity);
            return Task.CompletedTask;
        }
    }
}
