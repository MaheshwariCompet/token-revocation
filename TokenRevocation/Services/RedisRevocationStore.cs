using StackExchange.Redis;

namespace TokenRevocation.Services;

public class RedisRevocationStore : IRevocationStore
{
    private readonly IConnectionMultiplexer _redis;
    private const string KeyPrefix = "revoked-jti:";

    public RedisRevocationStore(IConnectionMultiplexer redis)
    {
        _redis = redis;
    }

    public async Task RevokeAsync(string jti, TimeSpan ttl)
    {
        var db = _redis.GetDatabase();
        // TTL = remaining lifetime of the token, so denylist never grows unbounded.
        await db.StringSetAsync(KeyPrefix + jti, "1", ttl);
    }

    public async Task<bool> IsRevokedAsync(string jti)
    {
        var db = _redis.GetDatabase();
        return await db.KeyExistsAsync(KeyPrefix + jti);
    }
}