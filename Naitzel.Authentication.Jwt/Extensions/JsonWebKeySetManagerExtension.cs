using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Naitzel.Authentication.Jwt.Configurations;
using Naitzel.Authentication.Jwt.Interfaces;
using Naitzel.Authentication.Jwt.Services;
using Naitzel.Authentication.Jwt.Middlewares;

namespace Naitzel.Authentication.Jwt.Extensions;

public static class JsonWebKeySetManagerExtension
{
    public static IServiceCollection AddJsonWebKey(this IServiceCollection services, IConfiguration configuration)
    {
        // Capturar configurações do arquivo config
        var jwtConfig = configuration.GetRequiredSection("JwtConfig");
        var securityOptions = configuration.GetRequiredSection("SecurityOptions");

        // Adicionar configurações JWT
        services.Configure<JwtConfig>(jwtConfig);
        services.Configure<SecurityOptions>(securityOptions);

        // Adicionar serviço gerador de JWT
        services.AddSingleton<IJwtService, JwtService>();

        var jwtService = services.BuildServiceProvider().GetRequiredService<IJwtService>();

        services
            .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(async options =>
            {
#if DEBUG
                options.IncludeErrorDetails = true;
#endif
                options.SaveToken = true;
                options.RequireHttpsMetadata = false;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    RequireSignedTokens = true,
                    RequireExpirationTime = true,
                    ValidAudience = jwtConfig.GetValue<string>("Audience"),
                    ValidateLifetime = true,
                    ValidateAudience = true,
                    ValidIssuer = jwtConfig.GetValue<string>("Issuer"),
                    ValidateIssuer = true,
                    IssuerSigningKey = await jwtService.GetPublicKey(),
                };
            });

        return services;
    }

    public static void UseJsonWebKey(this IApplicationBuilder app)
    {
        app.Map(new PathString("/jwks"), x => x.UseMiddleware<JwtServiceDiscoveryMiddleware>());

        app.UseAuthentication();
        app.UseAuthorization();
    }
}

