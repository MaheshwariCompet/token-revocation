namespace TokenRevocation.Models;

public record RegisterRequest(string Email, string Password);
public record LoginRequest(string Email, string Password);
public record LoginResponse(string AccessToken, DateTime ExpiresAt);