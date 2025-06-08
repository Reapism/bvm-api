using BVM.Core.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace BVM.Core.Infrastructure.Data
{
    public class BvmDbContext : DbContext
    {
        public const string ConnectionStringName = "BvmDb";

        private readonly ILogger<BvmDbContext> logger;
        [ActivatorUtilitiesConstructor]
        public BvmDbContext(DbContextOptions<BvmDbContext> options, ILogger<BvmDbContext> logger) : base(options)
        {
            this.logger = logger;
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            base.OnConfiguring(optionsBuilder);
        }

        public DbSet<Profile> Profiles { get; set; }
    }
}
