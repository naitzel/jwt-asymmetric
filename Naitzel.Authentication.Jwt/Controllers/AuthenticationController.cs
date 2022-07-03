using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Naitzel.Authentication.Jwt.Configurations;
using Naitzel.Authentication.Jwt.Interfaces;

namespace Naitzel.Authentication.Jwt.Controllers;

[Authorize]
[ApiController]
[Route("[controller]")]
public class AuthenticationController : ControllerBase
{
    private readonly ILogger<AuthenticationController> _logger;

    private readonly IJwtService _service;

    private readonly JwtConfig _config;

    public AuthenticationController(ILogger<AuthenticationController> logger, IJwtService service, IOptions<JwtConfig> config)
    {
        _logger = logger;
        _service = service;
        _config = config.Value;
    }

    [HttpGet]
    public IActionResult Me()
    {
        return Ok();
    }

    [HttpPost]
    [AllowAnonymous]
    public async Task<IActionResult> AutenticateAsync()
    {
        return Ok(await GenerateToken());
    }

    private async Task<string> GenerateToken()
    {
        JwtSecurityTokenHandler tokenHandler = new();
        ClaimsIdentity identityClaims = new();

        var token = tokenHandler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = _config.Issuer,
            Audience = _config.Audience,
            Subject = identityClaims,
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = await _service.GetPrivateKey(),
        });

        return tokenHandler.WriteToken(token);
    }
}
