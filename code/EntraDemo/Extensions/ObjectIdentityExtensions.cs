using Microsoft.Graph.Models;

namespace EntraDemo.Extensions;

public static class ObjectIdentityExtensions
{
    public static bool IsLinkedToAGoogleAccount(this ObjectIdentity oi) =>
        oi.SignInType == "federated" &&
        oi.Issuer == "google.com";
}
