using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using System.Security.Claims;

namespace EntraDemo.Helpers;

public static class AuthenticationHelper
{
    public static void SetupUserInContext(TokenValidatedContext context, ILogger logger, string? userId, string? userName)
    {
        if (!string.IsNullOrWhiteSpace(userId) && !string.IsNullOrWhiteSpace(userName))
        {
            var simplifiedClaims = CreateEntraUserClaims(userId, userName);
            var newIdentity = new ClaimsIdentity(simplifiedClaims, CookieAuthenticationDefaults.AuthenticationScheme);
            context.Principal = new ClaimsPrincipal(newIdentity);

            logger.LogInformation("Created simplified identity for user: {UserId} - {UserName}", userId, userName);
        }
    }

    public static List<Claim> CreateEntraUserClaims(string userId, string userName, string signInMethod = "CIAM") => [
        new(Constants.UserIdClaimType, userId),
        new(Constants.UserNameClaimType, userName),
        new(Constants.AuthProviderClaimType, "CIAM"),
        new(Constants.SignInMethodClaimType, signInMethod)
    ];
}
