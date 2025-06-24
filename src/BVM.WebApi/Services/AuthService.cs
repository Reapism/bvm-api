using BVM.Core.Dtos;
using BVM.Core.Entities;
using BVM.WebApi.Configurations;
using BVM.WebApi.Infrastructure.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Sweaj.Patterns.Dates;
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
        private readonly IOptions<JwtSettings> jwtOptions;
        private readonly IDateTimeProvider dateTimeProvider;
        private readonly IUnitOfWork unitOfWork;

        public AuthService(
            UserManager<AppUser> userManager,
            IOptions<JwtSettings> jwtOptions,
            IDateTimeProvider dateTimeProvider,
            IUnitOfWork unitOfWork)
        {
            this.userManager = userManager;
            this.jwtOptions = jwtOptions;
            this.dateTimeProvider = dateTimeProvider;
            this.unitOfWork = unitOfWork;
        }

        public async Task<AuthToken> RegisterAsync(RegisterRequest req)
        {
            var userIfExists = await userManager.FindByEmailAsync(req.Email);
            if (userIfExists is not null)
                return AuthToken.Failed();

            var user = new AppUser { UserName = req.Email, Email = req.Email };
            var createResult = await userManager.CreateAsync(user, req.Password);
            if (!createResult.Succeeded)
                return AuthToken.Failed();

            return await CreateAuthTokenAsync(user);
        }

        public async Task<AuthToken> LoginAsync(LoginRequest req)
        {
            var user = await userManager.FindByEmailAsync(req.Email);
            if (user is null || !await userManager.CheckPasswordAsync(user, req.Password))
                return AuthToken.Failed();

            return await CreateAuthTokenAsync(user);
        }

        public async Task<AuthToken> RefreshAsync(string refreshToken)
        {
            var repo = unitOfWork.GetRepository<AppUserToken>();
            var stored = await repo.Query()
                .FirstOrDefaultAsync(t =>
                    t.LoginProvider == RefreshTokenProvider &&
                    t.Name == RefreshTokenName &&
                    t.Value == refreshToken,
                    CancellationToken.None);

            if (stored is null || stored.IsRevoked || stored.Expires < dateTimeProvider.Now().DateTime)
                return AuthToken.Failed();

            // Invalidate old refresh token
            stored.InvalidateToken();
            await repo.UpdateAsync(stored);
            await unitOfWork.CommitAsync();

            var user = await userManager.FindByIdAsync(stored.UserId.ToString());
            return await CreateAuthTokenAsync(user!);
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

        private async Task<AuthToken> CreateAuthTokenAsync(AppUser user)
        {
            // Generate new access token
            var accessToken = GenerateAccessToken(user);
            // Generate and persist refresh token
            var refreshEntity = await CreateAndPersistRefreshTokenAsync(user.Id);

            return new AuthToken(
                IsSuccessful: true,
                AccessToken: accessToken,
                RefreshToken: refreshEntity.Value,
                ExpiresIn: (int)jwtOptions.Value.AccessTokenExpiration.TotalSeconds
            );
        }

        private async Task<AppUserToken> CreateAndPersistRefreshTokenAsync(Guid userId)
        {
            var repo = unitOfWork.GetRepository<AppUserToken>();
            var now = dateTimeProvider.Now().DateTime;
            var token = new AppUserToken
            {
                UserId = userId,
                LoginProvider = RefreshTokenProvider,
                Name = RefreshTokenName,
                Value = Guid.NewGuid().ToString(),
                Created = now,
                Expires = now.Add(jwtOptions.Value.RefreshTokenExpiration)
            };

            var userToken = await repo.Query().FirstOrDefaultAsync(e => e.UserId == userId);

            if (userToken is not null)
            {
                userToken.InvalidateToken();
                await repo.UpdateAsync(token);
            }
            else
            {
                await repo.AddAsync(token, CancellationToken.None);
            }

            await unitOfWork.CommitAsync();
            return token;
        }

        private string GenerateAccessToken(AppUser user)
        {
            var settings = jwtOptions.Value;
            var keyBytes = Convert.FromBase64String(settings.Secret);
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
                issuer: settings.Issuer,
                audience: settings.Audience,
                claims: claims,
                notBefore: dateTimeProvider.Now().DateTime,
                expires: dateTimeProvider.Now().DateTime.Add(settings.AccessTokenExpiration),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }
    }

}
