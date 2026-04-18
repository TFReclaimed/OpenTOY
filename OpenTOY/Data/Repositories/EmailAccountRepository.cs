using Microsoft.EntityFrameworkCore;
using OpenTOY.Data.Entities;

namespace OpenTOY.Data.Repositories;

public interface IEmailAccountRepository : IRepository<EmailAccountEntity>
{
    Task<EmailAccountEntity?> GetByEmailAsync(int serviceId, string email);
    Task<EmailAccountEntity?> GetByIdAsync(int serviceId, int userId);
    Task<bool> CheckEmailRegisteredAsync(int serviceId, string email);
    Task<bool> ChangeEmailAsync(int serviceId, string oldEmail, string newEmail);
}

public class EmailAccountRepository : RepositoryBase<EmailAccountEntity>, IEmailAccountRepository
{
    public EmailAccountRepository(AppDb db) : base(db)
    {
    }

    public async Task<EmailAccountEntity?> GetByEmailAsync(int serviceId, string email)
    {
        return await Db.EmailAccounts
            .Include(ea => ea.User)
            .FirstOrDefaultAsync(ea => ea.ServiceId == serviceId && ea.Email == email);
    }

    public async Task<EmailAccountEntity?> GetByIdAsync(int serviceId, int userId)
    {
        return await Db.EmailAccounts
            .Include(ea => ea.User)
            .FirstOrDefaultAsync(ea => ea.ServiceId == serviceId && ea.Id == userId);
    }

    public async Task<bool> CheckEmailRegisteredAsync(int serviceId, string email)
    {
        return await Db.EmailAccounts.AnyAsync(ea => ea.ServiceId == serviceId && ea.Email == email);
    }

    public async Task<bool> ChangeEmailAsync(int serviceId, string oldEmail, string newEmail)
    {
        var oldAccount = await Db.EmailAccounts
            .FirstOrDefaultAsync(ea => ea.ServiceId == serviceId && ea.Email == oldEmail);

        if (oldAccount is null)
        {
            return false;
        }

        await using var transaction = await Db.Database.BeginTransactionAsync();

        try
        {
            var newAccount = new EmailAccountEntity
            {
                Id = oldAccount.Id,
                ServiceId = oldAccount.ServiceId,
                Email = newEmail,
                Password = oldAccount.Password,
                Salt = oldAccount.Salt
            };

            Db.EmailAccounts.Remove(oldAccount);
            await Db.SaveChangesAsync();

            await Db.EmailAccounts.AddAsync(newAccount);
            await Db.SaveChangesAsync();

            await transaction.CommitAsync();

            return true;
        }
        catch
        {
            await transaction.RollbackAsync();
            return false;
        }
    }
}