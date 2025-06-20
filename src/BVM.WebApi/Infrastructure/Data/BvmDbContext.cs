using BVM.Core.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace BVM.WebApi.Infrastructure.Data
{
    public class BvmDbContext : IdentityDbContext<AppUser, AppRole, Guid, AppUserClaim, AppUserRole, AppUserLogin, AppRoleClaim, AppUserToken>
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

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<AppUserToken>(b =>
            {
                b.ToTable("AspNetUserTokens");
                b.Property(x => x.Created).IsRequired();
                b.Property(x => x.Expires).IsRequired();
                b.Property(x => x.Revoked).IsRequired(false);
            });
        }
    }
}
