using BVM.Core.Dtos;
using BVM.Core.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace BVM.WebApi.Services
{
    public record LoginResponse(string? Token);
    public class AuthService
    {
        private readonly UserManager<AppUser> userManager;

        public AuthService(UserManager<AppUser> userManager)
        {
            this.userManager = userManager;
        }
        public async Task<AuthToken> Login(LoginRequest req)
        {
            throw new NotImplementedException();
        }

        public Task<AuthToken> GenerateAuthToken()
        {
            throw new NotImplementedException();
        }
        public Task<AuthToken> GenerateRefreshToken()
        {
            throw new NotImplementedException();
        }
    }
}
