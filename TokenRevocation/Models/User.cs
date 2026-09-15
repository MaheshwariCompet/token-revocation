namespace TokenRevocation.Models;

public class User
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string Role { get; set; } = "User"; // "User" or "Admin"

    // Bumping this instantly invalidates every JWT already issued to this user,
    // even though JWTs themselves are stateless and can't be individually "deleted".
    public int TokenVersion { get; set; } = 0;
}