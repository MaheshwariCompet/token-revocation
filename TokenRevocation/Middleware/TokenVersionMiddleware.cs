using System;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.EntityFrameworkCore;
using TokenRevocation.Data;
using TokenRevocation.Services;
using TokenRevocation.Services;

namespace TokenRevocation.Middleware;

/// <summary>
/// Runs after JWT bearer authentication. Rejects a request (401) if:
///  1) the token's "tokenVersion" claim doesn't match the user's current version
///     in the DB (meaning "logout everywhere" happened after this token was issued), or
///  2) the token's "jti" is present in the single-token revocation denylist.
/// Both checks turn a normally-stateless JWT into one that can be revoked on demand.
/// </summary>
public class TokenVersionMiddleware
{
    private readonly RequestDelegate _next;

    public TokenVersionMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, AppDbContext db, IRevocationStore revocationStore)
    {
        if (context.User.Identity?.IsAuthenticated == true)
        {
            var subClaim = context.User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            var jtiClaim = context.User.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
            var versionClaim = context.User.FindFirst("tokenVersion")?.Value;

            if (subClaim is null || jtiClaim is null || versionClaim is null ||
                !Guid.TryParse(subClaim, out var userId) ||
                !int.TryParse(versionClaim, out var tokenVersion))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return;
            }

            if (await revocationStore.IsRevokedAsync(jtiClaim))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsync("Token has been revoked.");
                return;
            }

            var currentVersion = await db.Users
                .Where(u => u.Id == userId)
                .Select(u => u.TokenVersion)
                .FirstOrDefaultAsync();

            if (tokenVersion != currentVersion)
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsync("Token version stale — please log in again.");
                return;
            }
        }

        await _next(context);
    }
}

public static class TokenVersionMiddlewareExtensions
{
    public static IApplicationBuilder UseTokenVersionCheck(this IApplicationBuilder app)
        => app.UseMiddleware<TokenVersionMiddleware>();
}