namespace Naitzel.Authentication.Jwt.Configurations;

public class JwtConfig
{
    /// <summary>
    /// Destinatário do token, representa a aplicação que irá usá-lo.
    /// </summary>
    public string? Audience { get; init; }

    /// <summary>
    /// Emissor do token
    /// </summary>
    public string? Issuer { get; init; }
}

