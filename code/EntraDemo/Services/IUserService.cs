using Microsoft.Graph.Models;

namespace EntraDemo.Services;

public interface IUserService
{
    Task<bool> CreateUserInEntraIdAsync(CreateUserViewModel model);
    Task<List<UserInfo>> GetAllUsersAsync();
    Task<User?> GetUserByIdAsync(string userId);
    Task<User?> FindUserByGoogleIdAsync(string googleUserId);
    Task<bool> LinkGoogleAccountAsync(string userId, string googleUserId);
    Task<bool> UnlinkGoogleAccountAsync(string userId);
    Task<bool> IsGoogleAccountLinkedAsync(string userId);
    Task<string?> GetLinkedGoogleAccountAsync(string userId);
}