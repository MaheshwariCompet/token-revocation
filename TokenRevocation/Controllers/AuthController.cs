using System;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TokenRevocation.Data;
using TokenRevocation.Models;
using TokenRevocation.Services;
using LoginRequest = TokenRevocation.Models.LoginRequest;
using RegisterRequest = TokenRevocation.Models.RegisterRequest;


namespace TokenRevocation.Controllers;

[ApiController]
[Route("auth")]
public class AuthController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly AuthService _authService;

    public AuthController(AppDbContext db, AuthService authService)
    {
        _db = db;
        _authService = authService;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterRequest request)
    {
        if (await _db.Users.AnyAsync(u => u.Email == request.Email))
            return Conflict("Email already registered.");

        var user = new User
        {
            Email = request.Email,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password)
        };
        _db.Users.Add(user);
        await _db.SaveChangesAsync();
        return Created(string.Empty, new { user.Id, user.Email });
    }

    [HttpPost("login")]
    public async Task<ActionResult<LoginResponse>> Login(LoginRequest request)
    {
        var user = await _authService.ValidateCredentialsAsync(request.Email, request.Password);
        if (user is null) return Unauthorized("Invalid email or password.");

        var (token, expiresAt) = _authService.IssueAccessToken(user);
        return Ok(new LoginResponse(token, expiresAt));
    }

    /// <summary>Revokes only the token used to call this endpoint.</summary>
    [Authorize]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        var jti = User.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
        var expClaim = User.FindFirst(JwtRegisteredClaimNames.Exp)?.Value;
        if (jti is null || expClaim is null) return BadRequest();

        var expiresAt = DateTimeOffset.FromUnixTimeSeconds(long.Parse(expClaim)).UtcDateTime;
        await _authService.RevokeTokenAsync(jti, expiresAt);
        return NoContent();
    }

    /// <summary>Invalidates every token for the current user, on every device.</summary>
    [Authorize]
    [HttpPost("logout-all")]
    public async Task<IActionResult> LogoutAll()
    {
        var sub = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        if (sub is null || !Guid.TryParse(sub, out var userId)) return BadRequest();

        await _authService.LogoutAllDevicesAsync(userId);
        return NoContent();
    }
}