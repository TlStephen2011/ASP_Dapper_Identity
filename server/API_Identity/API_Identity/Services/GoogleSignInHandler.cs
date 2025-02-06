using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using API_Identity.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

namespace API_Identity.Services;

public class GoogleSignInHandler
{
    private readonly TokenHandler _tokenHandler;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IConfiguration _configuration;

    public GoogleSignInHandler(
        TokenHandler tokenHandler, 
        UserManager<ApplicationUser> userManager,
        IConfiguration configuration)
    {
        _tokenHandler = tokenHandler;
        _userManager = userManager;
        _configuration = configuration;
    }
    
    public async Task<string> SigninWithGoogle(string idToken)
    {
        var principal = await ValidateGoogleIdTokenAsync(idToken);

        if (principal == null)
        {
            return null;
        }
        
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
        
        var jwtToken = _tokenHandler.GenerateJwtToken(new ApplicationUser()
        {
            UserName = email,
            PasswordHash = "",
            Id = Guid.Empty 
        }, roles);

        return jwtToken;
    }
    
    private async Task<ClaimsPrincipal> ValidateGoogleIdTokenAsync(string idToken)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var jsonToken = tokenHandler.ReadToken(idToken) as JwtSecurityToken;

            if (jsonToken == null || jsonToken.Issuer != "https://accounts.google.com")
            {
                return null;
            }

            var googleKeys = await GetGooglePublicKeysAsync();
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidIssuer = "https://accounts.google.com",
                ValidAudience = _configuration.GetValue<string>("Authentication:Google:ClientId"),
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
            return null;
        }
    }

    private async Task<IEnumerable<SecurityKey>> GetGooglePublicKeysAsync()
    {
        var httpClient = new HttpClient();
        var keysResponse = await httpClient.GetStringAsync("https://www.googleapis.com/oauth2/v3/certs");
        var keys = Newtonsoft.Json.JsonConvert.DeserializeObject<GoogleKeys>(keysResponse);
        
        return keys.Keys.Select(key =>
        {
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
            
            throw new InvalidOperationException("Public key information is incomplete.");
        });
    }
    
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
        public string N { get; set; }
        [JsonPropertyName("e")]
        public string E { get; set; }
    }

    public class GoogleKeys
    {
        public List<GoogleKey> Keys { get; set; }
    }
}