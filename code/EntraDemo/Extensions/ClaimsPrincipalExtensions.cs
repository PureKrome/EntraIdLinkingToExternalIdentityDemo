using System.Security.Claims;

namespace EntraDemo.Extensions;

public static class ClaimsPrincipalExtensions
{
    public static string? GetUserId(this ClaimsPrincipal user) => user.FindFirst(Constants.UserIdClaimType)?.Value;
    public static string? GetUserName(this ClaimsPrincipal user) => user.FindFirst(Constants.UserNameClaimType)?.Value;
    public static string? GetAuthProvider(this ClaimsPrincipal user) => user.FindFirst(Constants.AuthProviderClaimType)?.Value;
    public static string? GetSignInMethod(this ClaimsPrincipal user) => user.FindFirst(Constants.SignInMethodClaimType)?.Value;
}
