using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using API_Identity.Models;
using API_Identity.Models.Dtos.Requests;
using API_Identity.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace API_Identity.Controllers;

[Route("/api/[controller]")]
[ApiController]
public class AuthController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IConfiguration _configuration;
    private readonly UserStore _userStore;

    public AuthController(
        UserManager<ApplicationUser> userManager,
        IConfiguration configuration,
        UserStore userStore)
    {
        _userManager = userManager;
        _configuration = configuration;
        _userStore = userStore;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequestDto model)
    {
        var user = new ApplicationUser { Id = Guid.NewGuid(), UserName = model.UserName };
        var result = await _userManager.CreateAsync(user, model.Password);
        
        if (result.Succeeded) return Ok("User registered successfully");
        return BadRequest(result.Errors);
    }
    
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequestDto request)
    {
        var user = await _userStore.FindByNameAsync(request.Username, CancellationToken.None);
        if (user == null || !await _userManager.CheckPasswordAsync(user, request.Password)) // Using CheckPasswordAsync
        {
            return Unauthorized(new { message = "Invalid username or password" });
        }

        var roles = await _userStore.GetRolesAsync(user, CancellationToken.None);
        
        var token = GenerateJwtToken(user, roles);
        return Ok(new { token });
    }

    [HttpGet("google")]
    public IActionResult Login()
    {
        // Redirect user to Google for authentication
        var redirectUrl = $"{Request.Scheme}://{Request.Host}/api/auth/google-response";
        var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
        return Challenge(properties, GoogleDefaults.AuthenticationScheme);
    }
    
    [HttpGet("google-response")]
    public async Task<IActionResult> GoogleResponse()
    {
        // This will authenticate the user and get their info from Google
        var authenticateResult = await HttpContext.AuthenticateAsync(GoogleDefaults.AuthenticationScheme);

        if (!authenticateResult.Succeeded)
        {
            return Unauthorized();
        }

        // Get the user information from Google
        var userInfo = authenticateResult.Principal;
        var email = userInfo?.FindFirst(ClaimTypes.Email)?.Value;

        // Generate Claims for Cookie authentication (not using the existing ClaimsIdentity directly)
        var claims = userInfo?.Claims.ToList() ?? new List<Claim>();
        claims.Add(new Claim(ClaimTypes.Name, email));

        // Create a new ClaimsIdentity for Cookies authentication
        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

        // Sign in the user with cookies (signing in via Cookies Authentication)
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, claimsPrincipal);

        // Optionally, generate a JWT for API access (if needed)
        var jwtToken = GenerateJwtToken(new ApplicationUser
        {
            UserName = email,
            Id = Guid.NewGuid()
        }, new List<string> { "User" });

        return Ok(new { JwtToken = jwtToken });
    }


    
    private string GenerateJwtToken(ApplicationUser user, IList<string> roles)
    {
        var jwtKey = _configuration["Jwt:Key"]!;
        var jwtIssuer = _configuration["Jwt:Issuer"]!;

        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.UniqueName, user.UserName),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        foreach (var role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }
        
        var token = new JwtSecurityToken(
            issuer: jwtIssuer,
            audience: jwtIssuer,
            claims: claims,
            expires: DateTime.UtcNow.AddHours(2),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
    
}