using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace API_Identity.Controllers;

[Route("api/[controller]")]
[ApiController]
[Authorize]
public class ProtectedController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetProtectedInfo()
    {
        return Ok(new
        {
            Username = User.Identity?.Name,
            Claims = User.Claims.Select(c => new { c.Type, c.Value })
        });
    }
    
    [Authorize(Roles = "Admin")]
    [HttpGet("admin")]
    public IActionResult GetAdminData()
    {
        return Ok("This is only accessible to admins.");
    }
}