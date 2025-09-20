using System.Security.Claims;

namespace EntraDemo.Extensions;

public static class ClaimsIdentityExtensions
{
    public static string? GetUPN(this ClaimsIdentity identity) =>
        identity.FindFirst(Constants.UPNClaimType)?.Value;

    public static string? GetPreferredUserName(this ClaimsIdentity identity) =>
        identity.FindFirst(Constants.PreferredUserNameClaimType)?.Value;

    public static string? GetCustomName(this ClaimsIdentity identity) =>
        identity.FindFirst(Constants.NameClaimType)?.Value;

    public static string? GetName(this ClaimsIdentity identity) =>
        identity.FindFirst(ClaimTypes.Name)?.Value;
}
