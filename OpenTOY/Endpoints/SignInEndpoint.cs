using System.Text.Json.Serialization;
using FastEndpoints;
using Microsoft.Extensions.Options;
using OpenTOY.Attributes;
using OpenTOY.Data.Entities;
using OpenTOY.Extensions;
using OpenTOY.Filters;
using OpenTOY.Options;
using OpenTOY.Services;
using OpenTOY.Utils;

namespace OpenTOY.Endpoints;

[CommonEncryption]
public class SignInEndpoint : Endpoint<SignInRequest, SignInResponse>
{
    private readonly IAccountService _accountService;
    
    private readonly IOptions<ServiceOptions> _serviceOptions;

    public SignInEndpoint(IAccountService accountService, IOptions<ServiceOptions> serviceOptions)
    {
        _accountService = accountService;
        _serviceOptions = serviceOptions;
    }

    public override void Configure()
    {
        Post("/sdk/signIn.nx");
        AllowAnonymous();
        AllowFormData(true);
        Options(x =>
        {
            x
                .AddEndpointFilter<JsonFilter>()
                .AddEndpointFilter<CommonDecryptionFilter>();
        });
    }

    public override async Task HandleAsync(SignInRequest req, CancellationToken ct)
    {
        var passwd = Env.IsProduction() ? "[REDACTED]" : req.Passwd;
        Logger.LogInformation("SignIn - Device: {DeviceType} UUID2: {Uuid2}, UserId: {UserId}, Passwd: {Passwd}, MemType: {MemType} Params: {Params}",
            req.DeviceInfo.Device, req.Uuid2, req.UserId, passwd, req.MemType, req.NpParams.ToString(Env.IsProduction()));

        var serviceExists = _serviceOptions.Value.Services.TryGetValue(req.NpParams.SvcId, out var serviceInfo);
        if (!serviceExists)
        {
            Logger.LogError("Service doesn't exist: {ServiceId}", req.NpParams.SvcId);
            await Send.NotFoundAsync();
            return;
        }

        if (!serviceInfo!.LoginMethods.Contains(req.MemType))
        {
            Logger.LogError("Login method not supported for service. ServiceId: {ServiceId}, MemType: {MemType}",
                req.NpParams.SvcId, req.MemType);

            var errorResponse = new SignInResponse
            {
                ErrorCode = 1,
                ErrorText = "Login method not supported for this service",
                Result = new ToyLoginResult()
            };

            await this.SendCommonEncryptedAsync(errorResponse);
            return;
        }

        UserEntity? user = null;
        if (req.MemType == (int) MembershipType.Email)
        {
            var (userEntity, error) = await _accountService.SignInEmailAsync(req);
            user = userEntity;
            
            if (error is not null)
            {
                Logger.LogWarning("Sign in failed for UserId: {UserId}. Error: {Error}",
                    req.UserId, error);

                var errorResponse = new SignInResponse
                {
                    ErrorCode = 1,
                    ErrorText = error,
                    Result = new ToyLoginResult()
                };
                
                await this.SendCommonEncryptedAsync(errorResponse);
                return;
            }
        }
        else if (req.MemType == (int) MembershipType.Guest)
        {
            user = await _accountService.GetOrCreateGuestAsync(req);
        }
        
        if (user is null)
        {
            Logger.LogWarning("User not found after sign in attempt. MemType: {MemType}, UserId: {UserId}",
                req.MemType, req.UserId);
            await Send.NotFoundAsync();
            return;
        }
        
        var serviceId = user.ServiceId;
        var userId = user.Id;
        
        var response = new SignInResponse
        {
            Result = new ToyLoginResult
            {
                Id = ToyUser.GenerateNpsn(serviceId, userId),
                Token = _accountService.GenerateJwtToken(serviceId, userId)
            }
        };

        await this.SendCommonEncryptedAsync(response);
    }
}

public class SignInRequest : BaseRequest
{
    public string Uuid2 { get; set; } = string.Empty;
    // Contains the email address
    public string? UserId { get; set; }
    public string Passwd { get; set; } = string.Empty;
    public int MemType { get; set; }
    [JsonPropertyName("optional")]
    public required DeviceInfo DeviceInfo { get; set; }
}

public class DeviceInfo
{
    public string Name { get; set; } = string.Empty;
    public string Device { get; set; } = string.Empty;
}

public class SignInResponse : BaseResponse
{
    public required ToyLoginResult Result { get; set; }
}

public class ToyLoginResult
{
    [JsonPropertyName("npSN")]
    public long Id { get; set; }
    [JsonPropertyName("npToken")]
    public string Token { get; set; } = string.Empty;
}