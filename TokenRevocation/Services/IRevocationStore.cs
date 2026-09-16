namespace TokenRevocation.Services;

/// <summary>
/// Denylist for individually-revoked access tokens (identified by their "jti" claim).
/// Used for immediate single-token revocation (e.g. "log out this one session now")
/// as opposed to TokenVersion, which invalidates ALL tokens for a user at once.
/// Entries only need to live as long as the token's own remaining lifetime.
/// </summary>
public interface IRevocationStore
{
    Task RevokeAsync(string jti, TimeSpan ttl);
    Task<bool> IsRevokedAsync(string jti);
}