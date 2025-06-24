using BVM.Core.Abstractions.Data;
using BVM.Core.Dtos;
using BVM.Core.Entities;
using BVM.WebApi.Configurations;
using BVM.WebApi.Infrastructure.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace BVM.WebApi.Services
{
    // Service interface
    public interface IAuthService
    {
        Task<AuthToken> RegisterAsync(RegisterRequest req);
        Task<AuthToken> LoginAsync(LoginRequest req);
        Task<AuthToken> RefreshAsync(string refreshToken);
        Task<bool> LogoutAsync(string refreshToken);
    }

    public class AuthService : IAuthService
    {
        private const string RefreshTokenProvider = "BVM";
        private const string RefreshTokenName = "RefreshToken";

        private readonly UserManager<AppUser> userManager;
        private readonly JwtSettings jwtSettings;
        private readonly IDateTimeProvider dateTimeProvider;
        private readonly IUnitOfWork unitOfWork;

        public AuthService(
            UserManager<AppUser> userManager,
            IOptions<JwtSettings> jwtOptions,
            IDateTimeProvider dateTimeProvider,
            IUnitOfWork unitOfWork)
        {
            this.userManager = userManager;
            this.jwtSettings = jwtOptions.Value;
            this.dateTimeProvider = dateTimeProvider;
            this.unitOfWork = unitOfWork;
        }

        public async Task<AuthToken> RegisterAsync(RegisterRequest req)
        {
            if (await userManager.FindByEmailAsync(req.Email) is not null)
                return AuthToken.Failed();

            var user = new AppUser { UserName = req.Email, Email = req.Email };
            var createResult = await userManager.CreateAsync(user, req.Password);
            if (!createResult.Succeeded)
                return AuthToken.Failed();

            try
            {
                return await GenerateAndSaveTokensAsync(user);
            }
            catch
            {
                // rollback orphan user
                await userManager.DeleteAsync(user);
                throw;
            }
        }

        public async Task<AuthToken> LoginAsync(LoginRequest req)
        {
            var user = await userManager.FindByEmailAsync(req.Email);
            if (user is null || !await userManager.CheckPasswordAsync(user, req.Password))
                return AuthToken.Failed();

            var now = dateTimeProvider.Now;
            var repo = unitOfWork.GetRepository<AppUserToken>();

            // reuse existing valid refresh token if present
            var existing = await repo.Query()
                .FirstOrDefaultAsync(t =>
                    t.UserId == user.Id &&
                    t.LoginProvider == RefreshTokenProvider &&
                    t.Name == RefreshTokenName &&
                    t.Revoked == null &&
                    t.Expires > now,
                    CancellationToken.None);

            var accessToken = GenerateAccessToken(user);
            if (existing is not null)
            {
                await unitOfWork.CommitAsync();
                return new AuthToken(
                    true,
                    accessToken,
                    existing.Value,
                    (int)jwtSettings.AccessTokenExpiration.TotalSeconds);
            }

            // no valid token exists, generate new
            return await GenerateAndSaveTokensAsync(user);
        }

        public async Task<AuthToken> RefreshAsync(string refreshToken)
        {
            var now = dateTimeProvider.Now;
            var repo = unitOfWork.GetRepository<AppUserToken>();
            var stored = await repo.Query()
                .FirstOrDefaultAsync(t =>
                    t.LoginProvider == RefreshTokenProvider &&
                    t.Name == RefreshTokenName &&
                    t.Value == refreshToken,
                    CancellationToken.None);

            if (stored is null || stored.IsRevoked || stored.Expires < now)
                return AuthToken.Failed();

            // invalidate old token
            stored.InvalidateToken();
            await repo.UpdateAsync(stored);
            await unitOfWork.CommitAsync();

            var user = await userManager.FindByIdAsync(stored.UserId.ToString());
            return await GenerateAndSaveTokensAsync(user!);
        }

        public async Task<bool> LogoutAsync(string refreshToken)
        {
            var repo = unitOfWork.GetRepository<AppUserToken>();
            var stored = await repo.Query()
                .FirstOrDefaultAsync(t =>
                    t.LoginProvider == RefreshTokenProvider &&
                    t.Name == RefreshTokenName &&
                    t.Value == refreshToken,
                    CancellationToken.None);

            if (stored is null)
                return false;

            stored.InvalidateToken();
            await repo.UpdateAsync(stored);
            await unitOfWork.CommitAsync();

            return true;
        }

        private async Task<AuthToken> GenerateAndSaveTokensAsync(AppUser user)
        {
            var accessToken = GenerateAccessToken(user);
            var refreshEntity = await CreateAndPersistRefreshTokenAsync(user.Id);
            return new AuthToken(
                true,
                accessToken,
                refreshEntity.Value,
                (int)jwtSettings.AccessTokenExpiration.TotalSeconds);
        }

        private async Task<AppUserToken> CreateAndPersistRefreshTokenAsync(Guid userId)
        {
            var repo = unitOfWork.GetRepository<AppUserToken>();
            var now = dateTimeProvider.Now;

            // revoke any existing tokens for this user
            var oldTokens = await repo.Query()
                .Where(t => t.UserId == userId && t.Name == RefreshTokenName)
                .ToListAsync(CancellationToken.None);
            foreach (var t in oldTokens)
            {
                await repo.DeleteAsync(t);
            }

            // create new
            var token = new AppUserToken
            {
                UserId = userId,
                LoginProvider = RefreshTokenProvider,
                Name = RefreshTokenName,
                Value = Guid.NewGuid().ToString(),
                Created = now,
                Expires = now.Add(jwtSettings.RefreshTokenExpiration)
            };
            await repo.AddAsync(token, CancellationToken.None);
            await unitOfWork.CommitAsync();
            return token;
        }

        private string GenerateAccessToken(AppUser user)
        {
            var now = dateTimeProvider.Now;
            var keyBytes = Convert.FromBase64String(jwtSettings.Secret);
            var securityKey = new SymmetricSecurityKey(keyBytes);
            var creds = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email!),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };
            var roles = userManager.GetRolesAsync(user).Result;
            claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));

            var jwt = new JwtSecurityToken(
                issuer: jwtSettings.Issuer,
                audience: jwtSettings.Audience,
                claims: claims,
                notBefore: now,
                expires: now.Add(jwtSettings.AccessTokenExpiration),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }
    }

}
