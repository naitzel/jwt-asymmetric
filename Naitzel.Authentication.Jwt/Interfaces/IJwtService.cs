using System.Collections.ObjectModel;
using Microsoft.IdentityModel.Tokens;

namespace Naitzel.Authentication.Jwt.Interfaces;

public interface IJwtService
{
    Task<SecurityKey> GetPublicKey();

    Task<SigningCredentials> GetPrivateKey();

    Task GenerateKey();

    // Task<SecurityKey> GetCurrentSecurityKey();
    // Task<SigningCredentials> GetCurrentSigningCredentials();
    // Task<EncryptingCredentials> GetCurrentEncryptingCredentials();

    Task<ReadOnlyCollection<JsonWebKey>> GetLastKeys();
}