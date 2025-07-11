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
        private readonly IAuthService authService;

        public AuthController(IAuthService authService)
        {
            this.authService = authService;

        }

        //[HttpPost]
        //[AllowAnonymous]
        //[Route("forgot-password")]
        //public async Task<IActionResult> ForgotPassword()
        //{

        //}

        //[HttpPost]
        //[AllowAnonymous]
        //[Route("reset-password")]
        //public async Task<IActionResult> ResetPassword()
        //{

        //}

        //[HttpPost]
        //[AllowAnonymous]
        //[Route("verify-email")]
        //public async Task<IActionResult> VerifyEmail()
        //{

        //}

        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<IActionResult> Register(
            [FromBody] RegisterRequest req)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var token = await authService.RegisterAsync(req);
            if (!token.IsSuccessful)
                return Conflict("User already exists or invalid data.");

            return Ok(new RegisterResponse(token));
        }

        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login(
            [FromBody] LoginRequest req)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var token = await authService.LoginAsync(req);
            if (!token.IsSuccessful)
                return Unauthorized();

            return Ok(new LoginResponse(token));
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh(
            [FromBody] RefreshRequest req)
        {
            var token = await authService.RefreshAsync(req.RefreshToken);
            if (!token.IsSuccessful)
                return Unauthorized();

            return Ok(new RefreshResponse(token));
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout(
            [FromBody] LogoutRequest req)
        {
            var success = await authService.LogoutAsync(req.RefreshToken);
            return Ok(new LogoutResponse(success));
        }
    }
}
