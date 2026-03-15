using System.Text.Json.Serialization;
using FastEndpoints;
using Microsoft.Extensions.Options;
using OpenTOY.Attributes;
using OpenTOY.Extensions;
using OpenTOY.Filters;
using OpenTOY.Options;
using OpenTOY.Services;

namespace OpenTOY.Endpoints;

[CommonEncryption]
public class ResetEmailPasswordEndpoint : Endpoint<ResetEmailPasswordRequest, ResetEmailPasswordResponse>
{
    private readonly IAccountService _accountService;

    private readonly IOptions<ServiceOptions> _serviceOptions;

    public ResetEmailPasswordEndpoint(IAccountService accountService, IOptions<ServiceOptions> serviceOptions)
    {
        _accountService = accountService;
        _serviceOptions = serviceOptions;
    }

    public override void Configure()
    {
        Post("/sdk/requestResetPasswordNPAA.nx");
        AllowAnonymous();
        AllowFormData(true);
        Options(x =>
        {
            x
                .AddEndpointFilter<JsonFilter>()
                .AddEndpointFilter<CommonDecryptionFilter>();
        });
    }

    public override async Task HandleAsync(ResetEmailPasswordRequest req, CancellationToken ct)
    {
        Logger.LogInformation("ResetEmailPassword - Email: {Email} ServiceId: {ServiceId}",
            req.Email, req.NpParams.SvcId);

        var serviceExists = _serviceOptions.Value.Services.TryGetValue(req.NpParams.SvcId, out _);
        if (!serviceExists)
        {
            Logger.LogError("Service doesn't exist: {ServiceId}", req.NpParams.SvcId);
            await Send.NotFoundAsync();
            return;
        }

        var isRegistered = await _accountService.SendPasswordResetEmailAsync(int.Parse(req.NpParams.SvcId), req.Email);

        var response = new ResetEmailPasswordResponse
        {
            ErrorCode = isRegistered ? 0 : 1,
            ErrorDetail = isRegistered ? string.Empty : "No account found with that email address"
        };

        await this.SendCommonEncryptedAsync(response);
    }
}

public class ResetEmailPasswordRequest : BaseRequest
{
    [JsonPropertyName("userID")]
    public string Email { get; set; } = string.Empty;
}

public class ResetEmailPasswordResponse : BaseResponse
{
}