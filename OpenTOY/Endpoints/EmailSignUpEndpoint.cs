using System.Text.Json.Serialization;
using FastEndpoints;
using Microsoft.Extensions.Options;
using OpenTOY.Attributes;
using OpenTOY.Extensions;
using OpenTOY.Filters;
using OpenTOY.Options;
using OpenTOY.Services;
using OpenTOY.Utils;

namespace OpenTOY.Endpoints;

[CommonEncryption]
public class EmailSignUpEndpoint : Endpoint<EmailSignUpRequest, EmailSignUpResponse>
{
    private readonly IAccountService _accountService;

    private readonly IOptions<ServiceOptions> _serviceOptions;

    public EmailSignUpEndpoint(IAccountService accountService, IOptions<ServiceOptions> serviceOptions)
    {
        _accountService = accountService;
        _serviceOptions = serviceOptions;
    }
    
    public override void Configure()
    {
        Post("/sdk/signUpNPAA.nx");
        AllowAnonymous();
        AllowFormData(true);
        Options(x =>
        {
            x
                .AddEndpointFilter<JsonFilter>()
                .AddEndpointFilter<CommonDecryptionFilter>();
        });
    }

    public override async Task HandleAsync(EmailSignUpRequest req, CancellationToken ct)
    {
        var passwd = Env.IsProduction() ? "[REDACTED]" : req.Passwd;
        Logger.LogInformation("EmailSignUp - UUID2: {Uuid2}, Email: {Email}, Passwd: {Passwd} Params: {Params}",
            req.Uuid2, req.Email, passwd, req.NpParams.ToString(Env.IsProduction()));
        
        var serviceExists = _serviceOptions.Value.Services.TryGetValue(req.NpParams.SvcId, out var serviceInfo);
        if (!serviceExists)
        {
            Logger.LogError("Service doesn't exist: {ServiceId}", req.NpParams.SvcId);
            await Send.NotFoundAsync();
            return;
        }

        if (!_accountService.IsValidEmail(req.Email))
        {
            var invalidEmailResponse = new EmailSignUpResponse
            {
                ErrorCode = 1,
                ErrorText = "Invalid email",
                Result = new ToyLoginResult()
            };

            await this.SendCommonEncryptedAsync(invalidEmailResponse);
            return;
        }

        var serviceId = int.Parse(req.NpParams.SvcId);
        var email = req.Email.ToLower();
        
        var emailRegistered = await _accountService.CheckEmailRegisteredAsync(serviceId, email);
        if (emailRegistered)
        {
            var emailExistsResponse = new EmailSignUpResponse
            {
                ErrorCode = 1,
                ErrorText = "Email already registered",
                Result = new ToyLoginResult()
            };
            
            await this.SendCommonEncryptedAsync(emailExistsResponse);
            return;
        }

        var user = await _accountService.CreateEmailAccountAsync(serviceId, serviceInfo!.Title, email, req.Passwd);

        var response = new EmailSignUpResponse
        {
            Result = new ToyLoginResult
            {
                Id = ToyUser.GenerateNpsn(serviceId, user.Id),
                Token = _accountService.GenerateJwtToken(serviceId, user.Id)
            }
        };

        await this.SendCommonEncryptedAsync(response);
    }
}

public class EmailSignUpRequest : BaseRequest
{
    public string Uuid2 { get; set; } = string.Empty;
    [JsonPropertyName("userID")]
    public string Email { get; set; } = string.Empty;
    public string Passwd { get; set; } = string.Empty;
}

public class EmailSignUpResponse : BaseResponse
{
    public required ToyLoginResult Result { get; set; }
}