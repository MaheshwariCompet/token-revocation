using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace TokenRevocation.Controllers;

[ApiController]
[Route("secure")]
[Authorize]
public class SecureController : ControllerBase
{
    /// <summary>
    /// Reachable only with a valid, non-revoked, current-version access token.
    /// Used to demonstrate revocation working end-to-end: call /auth/logout or
    /// /auth/logout-all with the same token, then retry this endpoint and see 401.
    /// </summary>
    [HttpGet("ping")]
    public IActionResult Ping() => Ok(new { message = "You are authenticated.", user = User.Identity?.Name });
}