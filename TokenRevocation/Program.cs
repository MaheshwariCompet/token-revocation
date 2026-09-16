using System;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using StackExchange.Redis;
using TokenRevocation.Data;
using TokenRevocation.Middleware;
using TokenRevocation.Services;

var builder = WebApplication.CreateBuilder(args);

// ---- Config ----
var jwtKey = builder.Configuration["Jwt:Key"] ?? "dev-only-secret-key-change-me-please-32chars+";
var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "TokenRevocation";
var jwtAudience = builder.Configuration["Jwt:Audience"] ?? "tokenrevocation-api";
builder.Configuration["Jwt:Key"] = jwtKey;
builder.Configuration["Jwt:Issuer"] = jwtIssuer;
builder.Configuration["Jwt:Audience"] = jwtAudience;

// ---- Database (SQLite for easy local/demo use; swap for SQL Server/Postgres in prod) ----
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("Default") ?? "Data Source=tokenrevocation.db"));

// ---- Revocation store: Redis if configured, otherwise in-memory fallback ----
var redisConnection = builder.Configuration["Redis:ConnectionString"];
if (!string.IsNullOrWhiteSpace(redisConnection))
{
    builder.Services.AddSingleton<IConnectionMultiplexer>(
        ConnectionMultiplexer.Connect(redisConnection));
    builder.Services.AddSingleton<IRevocationStore, RedisRevocationStore>();
}
else
{
    builder.Services.AddSingleton<IRevocationStore, InMemoryRevocationStore>();
}

builder.Services.AddScoped<TokenService>();
builder.Services.AddScoped<AuthService>();

// ---- Authentication ----
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwtIssuer,
            ValidateAudience = true,
            ValidAudience = jwtAudience,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
            ClockSkew = TimeSpan.FromSeconds(30)
        };
    });

builder.Services.AddAuthorization();
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Auto-create the SQLite DB on startup for easy demoing.
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.EnsureCreated();
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();

// Must run AFTER UseAuthentication (needs User.Claims) and BEFORE UseAuthorization
// (so a revoked/stale token never reaches an [Authorize] check).
app.UseTokenVersionCheck();

app.UseAuthorization();
app.MapControllers();

app.Run();