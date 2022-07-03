using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

public static class JwksExtension
{
    public static void SetJwksOptions(this JwtBearerOptions options, JwkOptions jwkOptions)
    {
        var httpClient = new HttpClient(options.BackchannelHttpHandler ?? new HttpClientHandler())
        {
            Timeout = options.BackchannelTimeout,
            MaxResponseContentBufferSize = 1024 * 1024 * 10 // 10 MB 
        };

        options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            jwkOptions.JwksUri,
            new JwksRetriever(),
            new HttpDocumentRetriever(httpClient) { RequireHttps = options.RequireHttpsMetadata });

        options.TokenValidationParameters.ValidateAudience = false;
        options.TokenValidationParameters.ValidIssuer = jwkOptions.Issuer;

        if (!string.IsNullOrEmpty(jwkOptions.Audience))
        {
            options.TokenValidationParameters.ValidateAudience = true;
            options.TokenValidationParameters.ValidAudience = jwkOptions.Audience;
        }
    }
}

public class JwkOptions
{
    public JwkOptions(string jwksUri, string? issuer = null, TimeSpan? cacheTime = null, string? audience = null)
    {
        JwksUri = jwksUri;
        var jwks = new Uri(jwksUri);
        // Issuer = issuer ?? $"{jwks.Scheme}://{jwks.Authority}";
        KeepFor = cacheTime ?? TimeSpan.FromMinutes(1);
        // Audience = audience;
    }

    public string Issuer { get; set; } = "api-naitzel";

    public string JwksUri { get; set; }

    public TimeSpan KeepFor { get; set; } = TimeSpan.FromMinutes(15);

    public string Audience { get; set; } = "api-naitzel";
}

public class JwksRetriever : IConfigurationRetriever<OpenIdConnectConfiguration>
{
    public Task<OpenIdConnectConfiguration> GetConfigurationAsync(string address, IDocumentRetriever retriever, CancellationToken cancel)
    {
        return GetAsync(address, retriever, cancel);
    }

    /// <summary>
    /// Retrieves a populated <see cref="OpenIdConnectConfiguration"/> given an address and an <see cref="IDocumentRetriever"/>.
    /// </summary>
    /// <param name="address">address of the jwks uri.</param>
    /// <param name="retriever">the <see cref="IDocumentRetriever"/> to use to read the jwks</param>
    /// <param name="cancel"><see cref="CancellationToken"/>.</param>
    /// <returns>A populated <see cref="OpenIdConnectConfiguration"/> instance.</returns>
    public static async Task<OpenIdConnectConfiguration> GetAsync(string address, IDocumentRetriever retriever, CancellationToken cancel)
    {
        if (string.IsNullOrWhiteSpace(address))
            throw LogHelper.LogArgumentNullException(nameof(address));

        if (retriever == null)
            throw LogHelper.LogArgumentNullException(nameof(retriever));

        IdentityModelEventSource.ShowPII = true;
        var doc = await retriever.GetDocumentAsync(address, cancel);
        LogHelper.LogVerbose("IDX21811: Deserializing the string: '{0}' obtained from metadata endpoint into openIdConnectConfiguration object.", doc);
        var jwks = new JsonWebKeySet(doc);
        var openIdConnectConfiguration = new OpenIdConnectConfiguration()
        {
            JsonWebKeySet = jwks,
            JwksUri = address,
        };
        foreach (var securityKey in jwks.GetSigningKeys())
            openIdConnectConfiguration.SigningKeys.Add(securityKey);

        return openIdConnectConfiguration;
    }
}