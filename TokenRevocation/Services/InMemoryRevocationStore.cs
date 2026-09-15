using System.Collections.Concurrent;

namespace TokenRevocation.Services;

/// <summary>
/// Fallback store for local dev/testing when Redis isn't configured.
/// Not suitable for multi-instance production deployments.
/// </summary>
public class InMemoryRevocationStore : IRevocationStore
{
    private readonly ConcurrentDictionary<string, DateTime> _revoked = new();

    public Task RevokeAsync(string jti, TimeSpan ttl)
    {
        _revoked[jti] = DateTime.UtcNow.Add(ttl);
        return Task.CompletedTask;
    }

    public Task<bool> IsRevokedAsync(string jti)
    {
        if (_revoked.TryGetValue(jti, out var expiry))
        {
            if (expiry > DateTime.UtcNow) return Task.FromResult(true);
            _revoked.TryRemove(jti, out _); // expired, clean up
        }
        return Task.FromResult(false);
    }
}