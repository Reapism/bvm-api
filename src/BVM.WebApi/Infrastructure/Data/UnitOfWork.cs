namespace BVM.WebApi.Infrastructure.Data
{
    public class UnitOfWork : IUnitOfWork, IDisposable
    {
        private readonly IServiceScope scope;
        private bool isDisposed;
        public UnitOfWork(IServiceProvider serviceProvider)
        {
            this.scope = serviceProvider.CreateScope();
        }

        public async Task<int> CommitAsync(CancellationToken cancellationToken = default)
        {
            var db = scope.ServiceProvider.GetRequiredService<BvmDbContext>();
            return await db.SaveChangesAsync(cancellationToken);
        }

        public IRepository<TEntity> GetRepository<TEntity>() where TEntity : class
        {
            return scope.ServiceProvider.GetRequiredService<IRepository<TEntity>>();
        }

        public void Dispose()
        {
            if (isDisposed)
            {
                return;
            }

            scope.Dispose();
            isDisposed = true;
        }
    }
}
