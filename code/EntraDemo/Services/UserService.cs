using Microsoft.Graph;
using Microsoft.Graph.Models;

namespace EntraDemo.Services;

public class UserService : IUserService
{
    
    private readonly GraphServiceClient _graphClient;
    private readonly string _entraDomain;
    private readonly ILogger<UserService> _logger;

    public UserService(GraphServiceClient graphClient, IConfiguration configuration, ILogger<UserService> logger)
    {
        _graphClient = graphClient;
        _entraDomain = configuration["AzureAd:Domain"] ?? throw new ArgumentException("AzureAd:Domain configuration is missing");
        _logger = logger;
    }

    public async Task<bool> CreateUserInEntraIdAsync(CreateUserViewModel model)
    {
        try
        {
            var user = new User
            {
                AccountEnabled = true,
                DisplayName = model.Name,
                GivenName = model.Name.Split(" ").First(),
                Surname = model.Name.Split(" ").Last(),
                MailNickname = model.Email.Split('@').First(),
                //UserPrincipalName = model.Email,
                UserPrincipalName = $"{Guid.NewGuid()}@{_entraDomain}",
                PasswordProfile = new PasswordProfile
                {
                    ForceChangePasswordNextSignIn = false,
                    Password = model.Password
                },
                Identities =
                [
                    new ObjectIdentity
                    {
                        SignInType = "emailAddress",
                        Issuer = _entraDomain,
                        IssuerAssignedId = model.Email
                    }
                ]
            };

            await _graphClient.Users.PostAsync(user);
            return true;
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Failed to create user in EntraID");
            return false;
        }
    }

    public async Task<List<UserInfo>> GetAllUsersAsync()
    {
        try
        {
            var users = await _graphClient.Users.GetAsync();
            if (users == null)
            {
                throw new Exception("Failed to retrieve users from EntraID");
            }


            return users.Value?.Select(u => new UserInfo
            {
                Id = u.Id,
                Name = u.DisplayName,
                Email = u.UserPrincipalName
            }).ToList() ?? [];
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Failed to get users from EntraID");
            return [];
        }
    }

    public async Task<User?> GetUserByIdAsync(string userId)
    {
        try
        {
            _logger.LogInformation("Getting user by ID: {UserId}", userId);
            
            // Try to get user by different ID types
            User? user = null;
            
            // First try as object ID (GUID format)
            if (Guid.TryParse(userId, out _))
            {
                _logger.LogInformation("Trying to get user by Object ID: {UserId}", userId);
                try
                {
                    user = await _graphClient.Users[userId].GetAsync(config =>
                    {
                        config.QueryParameters.Select = [
                            "id", 
                            "displayName", 
                            "userPrincipalName", 
                            "mail", 
                            "identities", 
                            "givenName", 
                            "surname"];
                    });
                    if (user != null)
                    {
                        _logger.LogInformation("Found user by Object ID: {UserPrincipalName}", user.UserPrincipalName);
                        return user;
                    }
                }
                catch (Exception exception)
                {
                    _logger.LogWarning(exception, "Failed to get user by Object ID: {UserId}", userId);
                }
            }
            
            // Try as UPN (email format)
            if (userId.Contains('@'))
            {
                _logger.LogInformation("Trying to get user by UPN: {UserId}", userId);
                try
                {
                    var users = await _graphClient.Users.GetAsync(config =>
                    {
                        config.QueryParameters.Select = [
                            "id",
                            "displayName", 
                            "userPrincipalName", 
                            "mail", 
                            "identities", 
                            "givenName", 
                            "surname"];
                        config.QueryParameters.Filter = $"userPrincipalName eq '{userId}'";
                    });
                    
                    user = users?.Value?.FirstOrDefault();
                    if (user != null)
                    {
                        _logger.LogInformation("Found user by UPN: {UserPrincipalName}", user.UserPrincipalName);
                        return user;
                    }
                }
                catch (Exception exception)
                {
                    _logger.LogWarning(exception, "Failed to get user by UPN: {UserId}", userId);
                }
            }
            
            _logger.LogError("User not found with ID: {UserId}", userId);
            return null;
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Failed to get user by ID: {UserId}", userId);
            return null;
        }
    }

    public async Task<User?> FindUserByGoogleIdAsync(string googleUserId)
    {
        try
        {
            // Search for users with the specific Google identity
            var users = await _graphClient.Users.GetAsync(config =>
            {
                config.QueryParameters.Select = [
                    "id", 
                    "displayName", 
                    "userPrincipalName", 
                    "mail", 
                    "identities", 
                    "givenName", 
                    "surname"];
                config.QueryParameters.Filter = $"identities/any(c:c/issuerAssignedId eq '{googleUserId}' and c/issuer eq 'google.com')";
            });

            return users?.Value?.FirstOrDefault();
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Failed to find user by Google ID: {GoogleUserId}", googleUserId);
            return null;
        }
    }

    public async Task<bool> LinkGoogleAccountAsync(string userId, string googleUserId)
    {
        try
        {
            // First, get the current user to check existing identities
            var user = await GetUserByIdAsync(userId);
            if (user == null)
            {
                _logger.LogError("User not found: {UserId}", userId);
                return false;
            }

            // Check if Google account is already linked
            var existingGoogleIdentity = user.Identities?.FirstOrDefault(oi => oi.IsLinkedToAGoogleAccount());

            if (existingGoogleIdentity != null)
            {
                _logger.LogWarning("Google account already linked for user: {UserId}", userId);
                return false;
            }

            // Check if this Google account is linked to another user
            var existingUser = await FindUserByGoogleIdAsync(googleUserId);
            if (existingUser != null && existingUser.Id != userId)
            {
                _logger.LogError("Google account {GoogleUserId} is already linked to another user: {ExistingUserId}", googleUserId, existingUser.Id);
                return false;
            }

            // Create a new list of identities including the Google one
            var identities = user.Identities?.ToList() ?? [];
            identities.Add(new ObjectIdentity
            {
                SignInType = "federated",
                Issuer = "google.com",
                IssuerAssignedId = googleUserId
            });

            // Update the user with the new identities
            var userUpdate = new User
            {
                Identities = identities
            };

            await _graphClient.Users[userId].PatchAsync(userUpdate);
            _logger.LogInformation("Successfully linked Google account {GoogleUserId} to user {UserId}", googleUserId, userId);
            return true;
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Failed to link Google account for user: {UserId}", userId);
            return false;
        }
    }

    public async Task<bool> UnlinkGoogleAccountAsync(string userId)
    {
        try
        {
            // Get the current user to check existing identities
            var user = await GetUserByIdAsync(userId);
            if (user == null)
            {
                _logger.LogError("User not found: {UserId}", userId);
                return false;
            }

            // Remove the Google identity
            var identities = user.Identities?.Where(oi => !oi.IsLinkedToAGoogleAccount()).ToList();

            if (identities == null || identities.Count == user.Identities?.Count)
            {
                _logger.LogWarning("No Google account linked for user: {UserId}", userId);
                return false;
            }

            // Update the user with the filtered identities
            var userUpdate = new User
            {
                Identities = identities
            };

            await _graphClient.Users[userId].PatchAsync(userUpdate);
            _logger.LogInformation("Successfully unlinked Google account from user {UserId}", userId);
            return true;
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Failed to unlink Google account for user: {UserId}", userId);
            return false;
        }
    }

    public async Task<bool> IsGoogleAccountLinkedAsync(string userId)
    {
        try
        {
            var user = await GetUserByIdAsync(userId);
            if (user == null)
            {
                return false;
            }

            return user.Identities?.Any(oi => oi.IsLinkedToAGoogleAccount()) ?? false;
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Failed to check Google account link status for user: {UserId}", userId);
            return false;
        }
    }

    public async Task<string?> GetLinkedGoogleAccountAsync(string userId)
    {
        try
        {
            var user = await GetUserByIdAsync(userId);
            if (user == null)
            {
                return null;
            }

            var googleIdentity = user.Identities?.FirstOrDefault(oi => oi.IsLinkedToAGoogleAccount());

            return googleIdentity?.IssuerAssignedId;
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Failed to get linked Google account for user: {UserId}", userId);
            return null;
        }
    }
}