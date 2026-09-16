using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using TokenRevocation.Models;

namespace TokenRevocation.Services;

public class TokenService
{
    private readonly IConfiguration _config;

    public TokenService(IConfiguration config)
    {
        _config = config;
    }

    /// <summary>
    /// Issues a short-lived access token. Embeds:
    /// - "tokenVersion": checked against the DB on every request; bumping it
    ///   server-side invalidates ALL tokens for the user at once ("logout everywhere").
    /// - "jti": a unique token id, used for single-token revocation via the denylist.
    /// - "aud": explicit audience, so a token minted for this API can't be replayed
    ///   against another service that shares the same signing key.
    /// </summary>
    public string GenerateAccessToken(User user, out string jti, out DateTime expiresAt)
    {
        jti = Guid.NewGuid().ToString();
        expiresAt = DateTime.UtcNow.AddMinutes(10);

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Jti, jti),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.Role, user.Role),
            new Claim("tokenVersion", user.TokenVersion.ToString())
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _config["Jwt:Issuer"],
            audience: _config["Jwt:Audience"],
            claims: claims,
            expires: expiresAt,
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}