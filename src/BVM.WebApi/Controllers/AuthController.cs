using BVM.Core.Dtos;
using BVM.Core.Entities;
using BVM.WebApi.Configurations;
using BVM.WebApi.Infrastructure.Data;
using BVM.WebApi.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace BVM.WebApi.Controllers
{
    public class AuthController : ApiControllerBase
    {
        private readonly AuthService authService;
        private readonly UserManager<AppUser> userManager;
        private readonly IConfiguration configuration;
        private readonly BvmDbContext context;
        private readonly JwtSettings jwtOptions;

        public AuthController(AuthService authService, UserManager<AppUser> userManager, IConfiguration configuration, BvmDbContext context, IOptions<JwtSettings> jwtOptions)
        {
            this.authService = authService;
            this.userManager = userManager;
            this.configuration = configuration;
            this.context = context;
            this.jwtOptions = jwtOptions.Value;
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("login")]
        [ProducesResponseType(typeof(AuthToken), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> Login([FromBody] LoginRequest req)
        {
            var user = await userManager.FindByEmailAsync(req.Email);

            if (user == null || !await userManager.CheckPasswordAsync(user, req.Password))
                return Unauthorized();

            // 2) build JWT access token (unchanged)
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.Key));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var expires = DateTime.UtcNow.AddMinutes(
                              configuration.GetValue<int>("Jwt:AccessTokenMinutes", 15));

            var jwtToken = new JwtSecurityToken(
                issuer: jwtOptions.Issuer,
                audience: jwtOptions.Audience,
                claims: new[] {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.UniqueName, user.UserName!),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                },
                notBefore: DateTime.UtcNow,
                expires: expires,
                signingCredentials: creds
            );
            var accessToken = new JwtSecurityTokenHandler().WriteToken(jwtToken);

            // 3) create & persist a refresh token via IdentityUserToken
            var refreshToken = new AppUserToken
            {
                UserId = user.Id,
                LoginProvider = "BVM",
                Name = Guid.NewGuid().ToString("N"),
                Created = DateTime.UtcNow,
                Expires = DateTime.UtcNow
                                   .AddDays(configuration.GetValue<int>("Jwt:RefreshTokenDays", 7))
            };
            context.Set<AppUserToken>().Add(refreshToken);
            await context.SaveChangesAsync();

            // 4) return both tokens
            return Ok(new AuthToken(true, accessToken, refreshToken.Name, (int)(expires - DateTime.UtcNow).TotalSeconds));
        }

        [HttpPost]
        
        [Route("logout")]
        public async Task<IActionResult> Logout()
        {
            throw new NotImplementedException();
        }
        [HttpPost]
        [Route("refresh")]
        public async Task<IActionResult> Refresh()
        {
            throw new NotImplementedException();
        }

        [HttpGet]
        [Route("me")]
        public async Task<IActionResult> Me()
        {
            throw new NotImplementedException();
        }
    }
}
