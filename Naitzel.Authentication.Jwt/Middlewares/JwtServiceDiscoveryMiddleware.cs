using System.Text.Json;
using System.Text.Json.Serialization;
using Naitzel.Authentication.Jwt.Interfaces;

namespace Naitzel.Authentication.Jwt.Middlewares;

public class JwtServiceDiscoveryMiddleware
{
    private readonly RequestDelegate _next;

    public JwtServiceDiscoveryMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task Invoke(HttpContext httpContext, IJwtService keyService)
    {
        var storedKeys = await keyService.GetLastKeys();
        var keys = new
        {
            keys = storedKeys
        };

        httpContext.Response.ContentType = "application/json";
        await httpContext.Response.WriteAsync(
            JsonSerializer.Serialize(keys, new JsonSerializerOptions()
            {
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
            })
        );
    }
}