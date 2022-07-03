using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Naitzel.Authentication.Jwt.Configurations;
using Naitzel.Authentication.Jwt.Interfaces;
using Newtonsoft.Json;

namespace Naitzel.Authentication.Jwt.Services;

public class JwtService : IJwtService, IDisposable
{
    private readonly JwtConfig _config;

    private readonly SecurityOptions _options;

    private readonly RSA rsaPublic;

    private readonly RSA rsaPrivate;

    public JwtService(IOptions<JwtConfig> config, IOptions<SecurityOptions> options)
    {
        _config = config.Value;
        _options = options.Value;

        rsaPublic = RSA.Create();
        rsaPrivate = RSA.Create();
    }

    public void Dispose()
    {
        rsaPublic?.Dispose();
        rsaPrivate?.Dispose();
    }

    public Task GenerateKey()
    {
        using (var rsa = RSA.Create())
        {
            string keysFolder = Path.GetDirectoryName(_options.PrivateKeyFilePath)!;
            if (!Directory.Exists(keysFolder))
            {
                Directory.CreateDirectory(keysFolder);
            }

            string privateKeyXml = rsa.ToXmlString(true);
            string publicKeyXml = rsa.ToXmlString(false);

            using (var privateFile = File.Create(_options.PrivateKeyFilePath))
            {
                privateFile.Write(Encoding.UTF8.GetBytes(privateKeyXml));
            }

            using (var publicFile = File.Create(_options.PublicKeyFilePath))
            {
                publicFile.Write(Encoding.UTF8.GetBytes(publicKeyXml));
            }

        }

        return Task.CompletedTask;
    }

    public Task<ReadOnlyCollection<JsonWebKey>> GetLastKeys()
    {
        rsaPrivate.FromXmlString(File.ReadAllText(_options.PrivateKeyFilePath));

        var key = new RsaSecurityKey(rsaPrivate);
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
        jwk.KeyId = "authentication";
        jwk.Use = "sig";
        jwk.Alg = "RS256";

        return Task.FromResult(
            new List<JsonWebKey>() { jwk }.AsReadOnly()
        );
    }

    public Task<SigningCredentials> GetPrivateKey()
    {
        rsaPrivate.FromXmlString(File.ReadAllText(_options.PrivateKeyFilePath));

        return Task.FromResult(
            new SigningCredentials(
                key: new RsaSecurityKey(rsaPrivate),
                algorithm: SecurityAlgorithms.RsaSha256
            )
        );
    }

    public Task<SecurityKey> GetPublicKey()
    {
        rsaPublic.FromXmlString(File.ReadAllText(_options.PublicKeyFilePath));
        return Task.FromResult(new RsaSecurityKey(rsaPublic) as SecurityKey);
    }
}