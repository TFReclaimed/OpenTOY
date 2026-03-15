using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using FastEndpoints;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using OpenTOY.Attributes;
using OpenTOY.Extensions;
using OpenTOY.Utils;

namespace OpenTOY.Auth;

public class TokenAuth : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly ITokenValidator _tokenValidator;
    
    public const string SchemeName = "Token";
    
    public TokenAuth(ITokenValidator tokenValidator, IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger, UrlEncoder encoder) : base(options, logger, encoder)
    {
        _tokenValidator = tokenValidator;
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!IsFastEndpoint() || IsPublicEndpoint())
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        string jsonParams;

        if (IsNoEncryption())
        {
            if (!Request.Headers.TryGetValue(Constants.ParamsKey, out var npParamsHeader))
            {
                return Task.FromResult(AuthenticateResult.Fail("Params header not present"));
            }

            jsonParams = Crypto.HexStringToAscii(npParamsHeader.ToString());
        }
        else
        {
            var keyError = GetKey(out var key, out var npParamsHeader);
            if (keyError is not null)
            {
                return Task.FromResult(AuthenticateResult.Fail(keyError));
            }

            jsonParams = Crypto.Decrypt(npParamsHeader!, key!);
        }

        var npParams = JsonSerializer.Deserialize<NpParams>(jsonParams, EndpointExtensions.SerializeOptions);
        if (npParams is null)
        {
            return Task.FromResult(AuthenticateResult.Fail("Invalid params"));
        }

        if (!_tokenValidator.IsValidToken(npParams.NpToken, out var jwt))
        {
            return Task.FromResult(AuthenticateResult.Fail("Invalid token"));
        }

        var identity = new ClaimsIdentity(jwt.Claims, SchemeName);
        var principal = new GenericPrincipal(identity, null);
        var ticket = new AuthenticationTicket(principal, SchemeName);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.ContentType = "application/json";

        // {"errorCode":5001,"result":{},"errorText":"인증이 유효하지 않습니다.","errorDetail":""}
        var response = new BaseResponse
        {
            ErrorCode = 5001,
            ErrorText = "인증이 유효하지 않습니다.",
            ErrorDetail = ""
        };

        var json = JsonSerializer.Serialize(response, EndpointExtensions.SerializeOptions);
        byte[] responseBytes;

        if (IsNoEncryption())
        {
            responseBytes = Encoding.UTF8.GetBytes(json);
        }
        else
        {
            var keyError = GetKey(out var key, out _);
            if (keyError is not null)
            {
                Response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }

            responseBytes = Crypto.Encrypt(Encoding.ASCII.GetBytes(json), key!);
        }

        await Response.Body.WriteAsync(responseBytes);
    }

    private string? GetKey(out byte[]? key, out string? npParams)
    {
        key = null;
        npParams = null;
        
        var headerPresent = Request.Headers.TryGetValue(Constants.ParamsKey, out var npParamsHeader);
        if (!headerPresent)
        {
            return "Params header not present";
        }
        
        npParams = npParamsHeader.ToString();

        if (IsCommonEncryption())
        {
            key = Encoding.ASCII.GetBytes(Constants.Key);
        }
        else
        {
            var npsnHeaderPresent = Request.Headers.TryGetValue("npsn", out var npsn);
            if (!npsnHeaderPresent)
            {
                return "npsn header not present";
            }
            
            var userKey = ToyCrypto.GetUserKey(npsn.ToString());
            if (userKey is null)
            {
                return "Invalid npsn";
            }
            
            key = userKey;
        }

        return null;
    }

    private bool IsNoEncryption()
    {
        var epDefinition = GetEndpointDefinition();

        return epDefinition?.EndpointAttributes?
            .OfType<NoEncryptionAttribute>()
            .Any() is true;
    }

    private bool IsPublicEndpoint()
    {
        return Context
            .GetEndpoint()?
            .Metadata.OfType<AllowAnonymousAttribute>()
            .Any() is null or true;
    }

    private bool IsCommonEncryption()
    {
        var epDefinition = GetEndpointDefinition();

        return epDefinition?.EndpointAttributes?
            .OfType<CommonEncryptionAttribute>()
            .Any() is true;
    }

    private bool IsFastEndpoint()
    {
        return GetEndpointDefinition() is not null;
    }

    private EndpointDefinition? GetEndpointDefinition()
    {
        return Context
            .GetEndpoint()?
            .Metadata.OfType<EndpointDefinition>()
            .FirstOrDefault();
    }
}