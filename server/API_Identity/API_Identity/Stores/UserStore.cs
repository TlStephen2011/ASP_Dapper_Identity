using System.Data;
using API_Identity.Models;
using Dapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.SqlClient;
#pragma warning disable CS1998 // Async method lacks 'await' operators and will run synchronously

namespace API_Identity.Stores;

public class UserStore : IUserPasswordStore<ApplicationUser>, IUserRoleStore<ApplicationUser>
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
    
    public async Task AddToRoleAsync(ApplicationUser user, string roleName, CancellationToken cancellationToken)
    {
        const string roleSql = "SELECT Id FROM Roles WHERE Name = @RoleName";
        const string userRoleSql = "INSERT INTO UserRoles (UserId, RoleId) VALUES (@UserId, @RoleId)";

        using var connection = CreateConnection();
        var roleId = await connection.QuerySingleOrDefaultAsync<int?>(roleSql, new { RoleName = roleName });
        if (roleId == null)
        {
            throw new Exception("Role not found.");
        }

        await connection.ExecuteAsync(userRoleSql, new { UserId = user.Id, RoleId = roleId });
    }

    public async Task RemoveFromRoleAsync(ApplicationUser user, string roleName, CancellationToken cancellationToken)
    {
        const string roleSql = "SELECT Id FROM Roles WHERE Name = @RoleName";
        const string userRoleSql = "DELETE FROM UserRoles WHERE UserId = @UserId AND RoleId = @RoleId";

        using var connection = CreateConnection();
        var roleId = await connection.QuerySingleOrDefaultAsync<int?>(roleSql, new { RoleName = roleName });
        if (roleId == null)
        {
            throw new Exception("Role not found.");
        }

        await connection.ExecuteAsync(userRoleSql, new { UserId = user.Id, RoleId = roleId });
    }
    
    public async Task<IList<string>> GetRolesAsync(ApplicationUser user, CancellationToken cancellationToken)
    {
        const string sql = @"
            SELECT r.Name 
            FROM Roles r
            JOIN UserRoles ur ON r.Id = ur.RoleId
            WHERE ur.UserId = @UserId";

        using var connection = CreateConnection();
        var roles = await connection.QueryAsync<string>(sql, new { UserId = user.Id });
        return roles.ToList();
    }
    
    public async Task<bool> IsInRoleAsync(ApplicationUser user, string roleName, CancellationToken cancellationToken)
    {
        const string sql = @"
            SELECT COUNT(1) 
            FROM UserRoles ur
            JOIN Roles r ON ur.RoleId = r.Id
            WHERE ur.UserId = @UserId AND r.Name = @RoleName";

        using var connection = CreateConnection();
        var count = await connection.ExecuteScalarAsync<int>(sql, new { UserId = user.Id, RoleName = roleName });
        return count > 0;
    }

    public async Task<IList<ApplicationUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken)
    {
        const string sql = @"
            SELECT u.*
            FROM Users u
            JOIN UserRoles ur ON u.Id = ur.UserId
            JOIN Roles r ON ur.RoleId = r.Id
            WHERE r.Name = @RoleName";

        using var connection = CreateConnection();
        var users = await connection.QueryAsync<ApplicationUser>(sql, new { RoleName = roleName });
        return users.ToList();
    }

    public void Dispose() { }
}
