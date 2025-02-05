using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using API_Identity.Models;
using API_Identity.Models.Dtos.Requests;
using API_Identity.Stores;
using Microsoft.AspNetCore.Authentication;
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
        if (user == null || !await _userManager.CheckPasswordAsync(user, request.Password))
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
        var redirectUrl = Url.Action("GenerateJwt", "Auth");
        // var redirectUrl = $"{Request.Scheme}://{Request.Host}/api/Auth/generate-jwt";
        var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
        return Challenge(properties, GoogleDefaults.AuthenticationScheme);
    }

    [HttpGet("google-response")]
    public async Task<IActionResult> GoogleResponse()
    {
        var authenticateResult = await HttpContext.AuthenticateAsync(GoogleDefaults.AuthenticationScheme);

        if (!authenticateResult.Succeeded)
        {
            return Unauthorized();
        }

        var userInfo = authenticateResult.Principal;
        var username = userInfo?.FindFirst(ClaimTypes.Email)?.Value;

        var existingUser = await _userManager.FindByNameAsync(username);
        IList<string> roles;
        if (existingUser is null)
        {
            await _userManager.CreateAsync(new ApplicationUser()
                { Id = Guid.NewGuid(), UserName = username, PasswordHash = "" });
            roles = new List<string> { "User" };
        }
        else
        {
            roles = await _userManager.GetRolesAsync(existingUser);
        }

        var jwtToken = GenerateJwtToken(new ApplicationUser
        {
            UserName = username,
            Id = Guid.NewGuid()
        }, roles);

        return Ok(new { JwtToken = jwtToken });
    }

    [HttpGet("generate-jwt")]
    public async Task<IActionResult> GenerateJwt()
    {
        var authenticateResult = await HttpContext.AuthenticateAsync(GoogleDefaults.AuthenticationScheme);

        if (!authenticateResult.Succeeded)
        {
            return Unauthorized();
        }

        var userInfo = authenticateResult.Principal;
        var username = userInfo?.FindFirst(ClaimTypes.Email)?.Value;

        var existingUser = await _userManager.FindByNameAsync(username);
        IList<string> roles;
        if (existingUser is null)
        {
            await _userManager.CreateAsync(new ApplicationUser()
                { Id = Guid.NewGuid(), UserName = username, PasswordHash = "" });
            roles = new List<string> { "User" };
        }
        else
        {
            roles = await _userManager.GetRolesAsync(existingUser);
        }

        var jwtToken = GenerateJwtToken(new ApplicationUser
        {
            UserName = username,
            Id = Guid.NewGuid()
        }, roles);

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

    // Google OAuth Callback: Only applies Google OAuth validation
    [HttpPost("google-response")]
    public async Task<IActionResult> GoogleResponse([FromBody] TokenRequest request)
    {
        var idToken = request.IdToken;

        if (string.IsNullOrEmpty(idToken))
        {
            return BadRequest("id_token is required.");
        }

        var principal = await ValidateGoogleIdTokenAsync(idToken);

        if (principal == null)
        {
            return Unauthorized();
        }

        // Extract user information from the principal
        var email = principal.FindFirst(ClaimTypes.Email)?.Value;

        var existingUser = await _userManager.FindByNameAsync(email);
        IList<string> roles;
        if (existingUser is null)
        {
            await _userManager.CreateAsync(new ApplicationUser()
                { Id = Guid.NewGuid(), UserName = email, PasswordHash = "" });
            roles = new List<string> { "User" };
        }
        else
        {
            roles = await _userManager.GetRolesAsync(existingUser);
        }
        
        // Your user management logic (create user or get existing)
        var jwtToken = GenerateJwtTokenForGoogleUser(email, roles);

        return Ok(new { JwtToken = jwtToken });
    }

    private async Task<ClaimsPrincipal> ValidateGoogleIdTokenAsync(string idToken)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var jsonToken = tokenHandler.ReadToken(idToken) as JwtSecurityToken;

            if (jsonToken == null || jsonToken.Issuer != "https://accounts.google.com")
            {
                return null; // Invalid issuer, reject the token
            }

            var googleKeys = await GetGooglePublicKeysAsync(); // Fetch Google public keys
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidIssuer = "https://accounts.google.com",
                ValidAudience = "1029886995860-5m4l2j4kd7u6hnte0qomqbbss2rvnkd0.apps.googleusercontent.com",
                IssuerSigningKeys = googleKeys,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            var principal = tokenHandler.ValidateToken(idToken, tokenValidationParameters, out var validatedToken);
            Console.WriteLine(validatedToken);
            return principal;
        }
        catch (Exception e)
        {
            return null; // Token validation failed
        }
    }

    private async Task<IEnumerable<SecurityKey>> GetGooglePublicKeysAsync()
    {
        var httpClient = new HttpClient();
        var keysResponse = await httpClient.GetStringAsync("https://www.googleapis.com/oauth2/v3/certs");
        var keys = Newtonsoft.Json.JsonConvert.DeserializeObject<GoogleKeys>(keysResponse);

        // Instead of using x5c, we can use `n` (modulus) and `e` (exponent) from the key to create RSA keys.
        return keys.Keys.Select(key =>
        {
            // If x5c is null or empty, we use the RSA modulus and exponent.
            if (!string.IsNullOrEmpty(key.N) && !string.IsNullOrEmpty(key.E))
            {
                var rsa = new RSACryptoServiceProvider();
                var parameters = new RSAParameters
                {
                    Modulus = Base64UrlDecode(key.N),
                    Exponent = Base64UrlDecode(key.E)
                };
                rsa.ImportParameters(parameters);
                return new RsaSecurityKey(rsa);
            }

            // Fallback in case neither x5c nor rsa parameters are available (shouldn't happen if Google's certs are standard)
            throw new InvalidOperationException("Public key information is incomplete.");
        });
    }

    // Decodes a base64 URL encoded string
    private byte[] Base64UrlDecode(string input)
    {
        var base64 = input
            .Replace("-", "+")
            .Replace("_", "/");

        switch (base64.Length % 4)
        {
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
        }

        return Convert.FromBase64String(base64);
    }


    private string GenerateJwtTokenForGoogleUser(string email, IList<string> roles)
    {
        // Generate JWT token for your own backend API
        // This should be signed using your own secret key
        return GenerateJwtToken(new ApplicationUser()
        {
            Id = Guid.NewGuid(),
            PasswordHash = "",
            UserName = email
        }, roles);
    }

    public class TokenRequest
    {
        public string IdToken { get; set; }
    }

    public class GoogleKey
    {
        [JsonPropertyName("kty")]
        public string Kty { get; set; }
        [JsonPropertyName("kid")]
        public string Kid { get; set; }
        [JsonPropertyName("use")]
        public string Use { get; set; }
        [JsonPropertyName("alg")]
        public string Alg { get; set; }
        [JsonPropertyName("n")]
        public string N { get; set; } // Modulus (Base64Url encoded)
        [JsonPropertyName("e")]
        public string E { get; set; } // Exponent (Base64Url encoded)
    }

    public class GoogleKeys
    {
        public List<GoogleKey> Keys { get; set; }
    }
}