using System.Text.RegularExpressions;
using FastEndpoints.Security;
using Microsoft.Extensions.Options;
using OpenTOY.Data.Entities;
using OpenTOY.Data.Repositories;
using OpenTOY.Emails.Views.Emails.AccountCreated;
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

    // Copied from https://emailregex.com/
    [GeneratedRegex("^(?(\")(\".+?(?<!\\\\)\"@)|(([0-9a-z]((\\.(?!\\.))|[-!#\\$%&'\\*\\+/=\\?\\^`\\{\\}\\|~\\w])*)(?<=[0-9a-z])@))(?(\\[)(\\[(\\d{1,3}\\.){3}\\d{1,3}\\])|(([0-9a-z][-\\w]*[0-9a-z]*\\.)+[a-z0-9][\\-a-z0-9]{0,22}[a-z0-9]))$", RegexOptions.IgnoreCase)]
    private static partial Regex EmailRegex();

    public AccountService(ILogger<AccountService> logger, IPasswordService passwordService,
        IEmailService emailService, IUserRepository userRepository, IEmailAccountRepository emailAccountRepository,
        IGuestAccountRepository guestAccountRepository, IOptions<ServiceOptions> serviceOptions,
        IOptions<JwtOptions> jwtOptions)
    {
        _logger = logger;
        _passwordService = passwordService;
        _emailService = emailService;
        _userRepository = userRepository;
        _emailAccountRepository = emailAccountRepository;
        _guestAccountRepository = guestAccountRepository;
        _serviceOptions = serviceOptions;
        _jwtOptions = jwtOptions;
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
        var isRegistered = await CheckEmailRegisteredAsync(serviceId, email);
        if (!isRegistered)
        {
            return false;
        }

        var serviceName = serviceId.ToString();
        if (_serviceOptions.Value.Services.TryGetValue(serviceName, out var serviceInfo))
        {
            serviceName = serviceInfo.Title;
        }

        var model = new ResetPasswordViewModel(email, serviceName, "");
        await _emailService.SendEmailAsync(email, $"{serviceName} Password Reset",
            "/Views/Emails/ResetPassword/ResetPasswordEmail.cshtml", model);
        return true;
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
}