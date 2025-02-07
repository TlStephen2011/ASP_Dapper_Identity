using API_Common.Exceptions;
using API_Common.Models;
using API_Identity.Models;
using API_Identity.Models.Dtos.Requests;
using API_Identity.Services;
using API_Identity.Stores;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using TokenHandler = API_Identity.Services.TokenHandler;

namespace API_Identity.Controllers;

[Route("/api/[controller]")]
[ApiController]
public class AuthController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly UserStore _userStore;
    private readonly TokenHandler _tokenHandler;
    private readonly GoogleSignInHandler _googleSignInHandler;
    private readonly ExceptionHandler _exceptionHandler;

    public AuthController(
        UserManager<ApplicationUser> userManager,
        UserStore userStore,
        TokenHandler tokenHandler,
        GoogleSignInHandler googleSignInHandler,
        ExceptionHandler exceptionHandler)
    {
        _userManager = userManager;
        _userStore = userStore;
        _tokenHandler = tokenHandler;
        _googleSignInHandler = googleSignInHandler;
        _exceptionHandler = exceptionHandler;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequestDto model)
    {
        return await _exceptionHandler.HandleExceptionAsync(nameof(AuthController), nameof(GoogleResponse), async () =>
        {
            var user = new ApplicationUser { Id = Guid.NewGuid(), UserName = model.UserName };
            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded) return Ok(new GenericResponseDto() { Message = "User successfully registered"});
            return BadRequest(result.Errors);
        });        
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequestDto request)
    {
        return await _exceptionHandler.HandleExceptionAsync(nameof(AuthController), nameof(GoogleResponse), async () =>
        {
            var user = await _userStore.FindByNameAsync(request.Username, CancellationToken.None);
            if (user == null || !await _userManager.CheckPasswordAsync(user, request.Password))
            {
                return Unauthorized(new { message = "Invalid username or password" });
            }

            var roles = await _userStore.GetRolesAsync(user, CancellationToken.None);

            var token = _tokenHandler.GenerateJwtToken(user, roles);
            return Ok(new { token });
        });        
    }
    
    [HttpPost("google-response")]
    public async Task<IActionResult> GoogleResponse([FromBody] GoogleSiginTokenRequestDto request)
    {
        return await _exceptionHandler.HandleExceptionAsync(nameof(AuthController), nameof(GoogleResponse), async () =>
        {
            var idToken = request.IdToken;

            var jwtToken = await _googleSignInHandler.SigninWithGoogle(idToken);

            if (jwtToken is null) return Unauthorized();

            return Ok(new { JwtToken = jwtToken });
        });
    }

}