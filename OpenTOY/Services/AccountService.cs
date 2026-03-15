using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.RegularExpressions;
using FastEndpoints.Security;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using OpenTOY.Data.Entities;
using OpenTOY.Data.Repositories;
using OpenTOY.Emails.Views.Emails.AccountCreated;
using OpenTOY.Emails.Views.Emails.EmailChanged;
using OpenTOY.Emails.Views.Emails.PasswordChanged;
using OpenTOY.Emails.Views.Emails.ResetPassword;
using OpenTOY.Endpoints;
using OpenTOY.Options;

namespace OpenTOY.Services;

public interface IAccountService
{
    Task<(UserEntity? user, string error)> SignInAsync(int serviceId, string email, string password);
    Task<bool> ChangePasswordAsync(int serviceId, string email, string newPassword);
    Task<bool> ChangeEmailAsync(int serviceId, string oldEmail, string newEmail);
    Task<UserEntity?> GetOrCreateGuestAsync(SignInRequest req);
    Task<(UserEntity? user, string? error)> SignInEmailAsync(SignInRequest req);
    Task<UserEntity> CreateEmailAccountAsync(int serviceId, string serviceName, string email, string password);
    Task<bool> CheckEmailRegisteredAsync(int serviceId, string email);
    Task<bool> SendPasswordResetEmailAsync(int serviceId, string email);
    bool IsPasswordResetTokenValid(string token);
    Task<bool> ResetPasswordWithTokenAsync(string token, string newPassword);
    string GenerateJwtToken(int serviceId, int userId);
    bool IsValidEmail(string email);
}

public partial class AccountService : IAccountService
{
    private readonly ILogger<AccountService> _logger;

    private readonly IPasswordService _passwordService;

    private readonly IEmailService _emailService;

    private readonly IUserRepository _userRepository;
    
    private readonly IEmailAccountRepository _emailAccountRepository;
    
    private readonly IGuestAccountRepository _guestAccountRepository;

    private readonly IOptions<ServiceOptions> _serviceOptions;

    private readonly IOptions<JwtOptions> _jwtOptions;

    private readonly IOptions<PasswordResetOptions> _passwordResetOptions;

    private readonly ITimeLimitedDataProtector _passwordResetTokenProtector;

    // Copied from https://emailregex.com/
    [GeneratedRegex("^(?(\")(\".+?(?<!\\\\)\"@)|(([0-9a-z]((\\.(?!\\.))|[-!#\\$%&'\\*\\+/=\\?\\^`\\{\\}\\|~\\w])*)(?<=[0-9a-z])@))(?(\\[)(\\[(\\d{1,3}\\.){3}\\d{1,3}\\])|(([0-9a-z][-\\w]*[0-9a-z]*\\.)+[a-z0-9][\\-a-z0-9]{0,22}[a-z0-9]))$", RegexOptions.IgnoreCase)]
    private static partial Regex EmailRegex();

    public AccountService(ILogger<AccountService> logger, IPasswordService passwordService,
        IEmailService emailService, IUserRepository userRepository, IEmailAccountRepository emailAccountRepository,
        IGuestAccountRepository guestAccountRepository, IOptions<ServiceOptions> serviceOptions,
        IOptions<JwtOptions> jwtOptions, IOptions<PasswordResetOptions> passwordResetOptions,
        IDataProtectionProvider dataProtectionProvider)
    {
        _logger = logger;
        _passwordService = passwordService;
        _emailService = emailService;
        _userRepository = userRepository;
        _emailAccountRepository = emailAccountRepository;
        _guestAccountRepository = guestAccountRepository;
        _serviceOptions = serviceOptions;
        _jwtOptions = jwtOptions;
        _passwordResetOptions = passwordResetOptions;
        _passwordResetTokenProtector = dataProtectionProvider
            .CreateProtector("OpenTOY.PasswordReset")
            .ToTimeLimitedDataProtector();
    }

    public async Task<(UserEntity? user, string error)> SignInAsync(int serviceId, string email, string password)
    {
        var emailAccountEntity = await _emailAccountRepository.GetByEmailAsync(serviceId, email.ToLower());
        if (emailAccountEntity is null)
        {
            return (null, "Invalid email or password");
        }

        if (!_passwordService.VerifyPassword(password, emailAccountEntity.Password, emailAccountEntity.Salt))
        {
            return (null, "Invalid email or password");
        }

        return (emailAccountEntity.User!, string.Empty);
    }

    public async Task<bool> ChangePasswordAsync(int serviceId, string email, string newPassword)
    {
        var emailAccountEntity = await _emailAccountRepository.GetByEmailAsync(serviceId, email.ToLower());
        if (emailAccountEntity is null)
        {
            return false;
        }

        var hashedPassword = _passwordService.HashPassword(newPassword, out var salt);
        emailAccountEntity.Password = hashedPassword;
        emailAccountEntity.Salt = Convert.ToHexString(salt);

        await _emailAccountRepository.UpdateAsync(emailAccountEntity);

        var serviceName = GetServiceName(serviceId);
        var model = new PasswordChangedViewModel(email, serviceName);
        await _emailService.SendEmailAsync(email, "OpenTOY Password Changed",
            "/Views/Emails/PasswordChanged/PasswordChangedEmail.cshtml", model);

        return true;
    }

    public async Task<bool> ChangeEmailAsync(int serviceId, string oldEmail, string newEmail)
    {
        var emailAccountEntity = await _emailAccountRepository.GetByEmailAsync(serviceId, oldEmail.ToLower());
        if (emailAccountEntity is null)
        {
            return false;
        }

        if (await _emailAccountRepository.CheckEmailRegisteredAsync(serviceId, newEmail.ToLower()))
        {
            return false;
        }

        emailAccountEntity.Email = newEmail.ToLower();
        await _emailAccountRepository.UpdateAsync(emailAccountEntity);

        var serviceName = GetServiceName(serviceId);
        var model = new EmailChangedViewModel(oldEmail, newEmail, serviceName);
        await _emailService.SendEmailAsync(oldEmail, "OpenTOY Email Changed",
            "/Views/Emails/EmailChanged/EmailChangedEmail.cshtml", model);

        return true;
    }

    public async Task<UserEntity?> GetOrCreateGuestAsync(SignInRequest req)
    {
        var serviceId = int.Parse(req.NpParams.SvcId);
        var deviceId = req.Uuid2;

        if (deviceId.Length != 16 && deviceId.Length != 36)
        {
            _logger.LogWarning("Invalid device ID length for guest account: {DeviceId}", deviceId);
            return null;
        }

        var guestAccountEntity = await _guestAccountRepository.GetByIdAsync(serviceId, deviceId);
        if (guestAccountEntity is not null)
        {
            return guestAccountEntity.User!;
        }
        
        var userEntity = new UserEntity
        {
            ServiceId = serviceId,
            MembershipType = MembershipType.Guest
        };
        
        await _userRepository.AddAsync(userEntity);
        
        var guestAccount = new GuestAccountEntity
        {
            Id = userEntity.Id,
            ServiceId = userEntity.ServiceId,
            DeviceId = deviceId
        };
        
        await _guestAccountRepository.AddAsync(guestAccount);
        
        return userEntity;
    }

    public async Task<(UserEntity? user, string? error)> SignInEmailAsync(SignInRequest req)
    {
        var serviceId = int.Parse(req.NpParams.SvcId);
        
        var emailAccountEntity = await _emailAccountRepository.GetByEmailAsync(serviceId, req.UserId!.ToLower());
        if (emailAccountEntity is null)
        {
            return (null, "Email not found");
        }

        if (!_passwordService.VerifyPassword(req.Passwd, emailAccountEntity.Password, emailAccountEntity.Salt))
        {
            return (null, "Invalid password");
        }
        
        return (emailAccountEntity.User!, null);
    }

    public async Task<UserEntity> CreateEmailAccountAsync(int serviceId, string serviceName, string email, string password)
    {
        var hashedPassword = _passwordService.HashPassword(password, out var salt);
        
        var userEntity = new UserEntity
        {
            ServiceId = serviceId,
            MembershipType = MembershipType.Email
        };
        
        await _userRepository.AddAsync(userEntity);
        
        var emailAccountEntity = new EmailAccountEntity
        {
            Id = userEntity.Id,
            ServiceId = userEntity.ServiceId,
            Email = email,
            Password = hashedPassword,
            Salt = Convert.ToHexString(salt)
        };
        
        await _emailAccountRepository.AddAsync(emailAccountEntity);

        var model = new AccountCreatedEmailViewModel(email, serviceName);
        await _emailService.SendEmailAsync(email, "Welcome to OpenTOY",
            "/Views/Emails/AccountCreated/AccountCreatedEmail.cshtml", model);

        return userEntity;
    }

    public async Task<bool> CheckEmailRegisteredAsync(int serviceId, string email)
    {
        return await _emailAccountRepository.CheckEmailRegisteredAsync(serviceId, email.ToLower());
    }

    public async Task<bool> SendPasswordResetEmailAsync(int serviceId, string email)
    {
        var normalizedEmail = email.ToLower();
        var isRegistered = await CheckEmailRegisteredAsync(serviceId, normalizedEmail);
        if (!isRegistered)
        {
            return false;
        }

        var tokenPayload = new PasswordResetTokenPayload(serviceId, normalizedEmail);
        var tokenJson = JsonSerializer.Serialize(tokenPayload);
        var tokenLifetime = TimeSpan.FromMinutes(_passwordResetOptions.Value.TokenLifetimeMinutes);
        var token = _passwordResetTokenProtector.Protect(tokenJson, tokenLifetime);

        var serviceName = GetServiceName(serviceId);
        var resetBaseUrl = _passwordResetOptions.Value.ResetPageBaseUrl.TrimEnd('/');
        var resetLink = $"{resetBaseUrl}/reset-password?token={Uri.EscapeDataString(token)}";
        var model = new ResetPasswordViewModel(email, serviceName, resetLink,
            (int) Math.Ceiling(tokenLifetime.TotalMinutes));
        await _emailService.SendEmailAsync(email, $"{serviceName} Password Reset",
            "/Views/Emails/ResetPassword/ResetPasswordEmail.cshtml", model);
        return true;
    }

    public bool IsPasswordResetTokenValid(string token)
    {
        return TryReadPasswordResetToken(token, out _);
    }

    public async Task<bool> ResetPasswordWithTokenAsync(string token, string newPassword)
    {
        if (!TryReadPasswordResetToken(token, out var payload))
        {
            return false;
        }

        return await ChangePasswordAsync(payload.ServiceId, payload.Email, newPassword);
    }

    public string GenerateJwtToken(int serviceId, int userId)
    {
        // JWTs are supposed to be short-lived, but I haven't figured out how to get TOY to refresh them yet
        // Or if that's even something it can do
        var jwtToken = JwtBearer.CreateToken(o =>
        {
            o.SigningKey = _jwtOptions.Value.Key;
            o.ExpireAt = DateTime.UtcNow.AddYears(5);
            o.User["UserId"] = userId.ToString();
            o.User["ServiceId"] = serviceId.ToString();
        });

        return jwtToken;
    }

    public bool IsValidEmail(string email)
    {
        return EmailRegex().IsMatch(email);
    }

    private string GetServiceName(int serviceId)
    {
        var serviceName = serviceId.ToString();
        if (_serviceOptions.Value.Services.TryGetValue(serviceName, out var serviceInfo))
        {
            serviceName = serviceInfo.Title;
        }

        return serviceName;
    }

    private bool TryReadPasswordResetToken(string token, [NotNullWhen(true)] out PasswordResetTokenPayload? payload)
    {
        payload = null;
        if (string.IsNullOrWhiteSpace(token))
        {
            return false;
        }

        try
        {
            var tokenJson = _passwordResetTokenProtector.Unprotect(token, out _);
            var tokenPayload = JsonSerializer.Deserialize<PasswordResetTokenPayload>(tokenJson);

            if (tokenPayload is null)
            {
                return false;
            }

            payload = tokenPayload with
            {
                Email = tokenPayload.Email.ToLower()
            };

            return true;
        }
        catch
        {
            return false;
        }
    }

    public record PasswordResetTokenPayload(int ServiceId, string Email);
}