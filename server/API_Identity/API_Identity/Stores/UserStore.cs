using System.Data;
using API_Identity.Models;
using Dapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.SqlClient;
#pragma warning disable CS1998 // Async method lacks 'await' operators and will run synchronously

namespace API_Identity.Stores;

public class UserStore : IUserPasswordStore<ApplicationUser>
{
    private readonly string _connectionString;

    public UserStore(IConfiguration configuration)
    {
        _connectionString = configuration.GetConnectionString("DatabaseConnection");
    }
    
    private IDbConnection CreateConnection() => new SqlConnection(_connectionString);

    public async Task<IdentityResult> CreateAsync(ApplicationUser user, CancellationToken cancellationToken)
    {
        const string sql = "INSERT INTO Users (Id, UserName, PasswordHash) VALUES (@Id, @UserName, @PasswordHash)";
        using var connection = CreateConnection();
        await connection.ExecuteAsync(sql, user);
        return IdentityResult.Success;
    }

    public async Task<ApplicationUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
    {
        const string sql = "SELECT * FROM Users WHERE Id = @Id";
        using var connection = CreateConnection();
        return await connection.QuerySingleOrDefaultAsync<ApplicationUser>(sql, new { Id = Guid.Parse(userId) });
    }

    public async Task<ApplicationUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
    {
        const string sql = "SELECT * FROM Users WHERE UserName = @UserName";
        using var connection = CreateConnection();
        return await connection.QuerySingleOrDefaultAsync<ApplicationUser>(sql, new { UserName = normalizedUserName });
    }

    public async Task<string> GetUserIdAsync(ApplicationUser user, CancellationToken cancellationToken)
        => user.Id.ToString();

    public async Task<string> GetUserNameAsync(ApplicationUser user, CancellationToken cancellationToken)
        => user.UserName;

    public async Task SetUserNameAsync(ApplicationUser user, string userName, CancellationToken cancellationToken)
        => user.UserName = userName;

    public async Task SetNormalizedUserNameAsync(ApplicationUser user, string normalizedName, CancellationToken cancellationToken) 
    { }

    public async Task<string> GetNormalizedUserNameAsync(ApplicationUser user, CancellationToken cancellationToken) 
        => user.UserName.ToUpper();

    public async Task SetPasswordHashAsync(ApplicationUser user, string passwordHash, CancellationToken cancellationToken)
        => user.PasswordHash = passwordHash;

    public async Task<string> GetPasswordHashAsync(ApplicationUser user, CancellationToken cancellationToken)
        => user.PasswordHash;

    public async Task<bool> HasPasswordAsync(ApplicationUser user, CancellationToken cancellationToken)
        => !string.IsNullOrEmpty(user.PasswordHash);

    public Task<IdentityResult> DeleteAsync(ApplicationUser user, CancellationToken cancellationToken) => throw new NotImplementedException();
    public Task<IdentityResult> UpdateAsync(ApplicationUser user, CancellationToken cancellationToken) => throw new NotImplementedException();
    public void Dispose() { }
}
