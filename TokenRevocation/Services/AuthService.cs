using Microsoft.EntityFrameworkCore;
using System;
using TokenRevocation.Data;
using TokenRevocation.Models;
using TokenRevocation.Services;

namespace TokenRevocation.Services;

public class AuthService
{
    private readonly AppDbContext _db;
    private readonly TokenService _tokenService;
    private readonly IRevocationStore _revocationStore;

    public AuthService(AppDbContext db, TokenService tokenService, IRevocationStore revocationStore)
    {
        _db = db;
        _tokenService = tokenService;
        _revocationStore = revocationStore;
    }

    public async Task<User?> ValidateCredentialsAsync(string email, string password)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == email);
        if (user is null) return null;
        return BCrypt.Net.BCrypt.Verify(password, user.PasswordHash) ? user : null;
    }

    public (string token, DateTime expiresAt) IssueAccessToken(User user)
    {
        var token = _tokenService.GenerateAccessToken(user, out _, out var expiresAt);
        return (token, expiresAt);
    }

    /// <summary>
    /// Revokes a single token immediately (e.g. "log out this device now"),
    /// without affecting the user's other active sessions.
    /// </summary>
    public async Task RevokeTokenAsync(string jti, DateTime tokenExpiresAt)
    {
        var ttl = tokenExpiresAt - DateTime.UtcNow;
        if (ttl <= TimeSpan.Zero) return; // already expired, nothing to do
        await _revocationStore.RevokeAsync(jti, ttl);
    }

    /// <summary>
    /// Invalidates every access token ever issued to this user, instantly,
    /// regardless of how many are still unexpired or which devices hold them.
    /// </summary>
    public async Task LogoutAllDevicesAsync(Guid userId)
    {
        var user = await _db.Users.FindAsync(userId);
        if (user is null) return;

        user.TokenVersion++;
        await _db.SaveChangesAsync();
    }
}