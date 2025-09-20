using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace EntraDemo.Controllers;

public class AccountController(IUserService userService) : Controller
{
    public IActionResult Login()
    {
        var properties = new AuthenticationProperties 
        { 
            RedirectUri = Url.Action("Profile", "Home")
        };
        
        return Challenge(properties, OpenIdConnectDefaults.AuthenticationScheme);
    }

    public async Task<IActionResult> Logout()
    {
        // All users are CIAM users, so always sign out of both schemes
        var properties = new AuthenticationProperties
        {
            RedirectUri = Url.Action("Index", "Home")
        };

        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return SignOut(properties, OpenIdConnectDefaults.AuthenticationScheme);
    }

    [Authorize]
    public IActionResult LinkGoogle()
    {
        var userId = User.GetUserId();

        if (string.IsNullOrWhiteSpace(userId))
        {
            TempData["Error"] = "Invalid user authentication state for linking";
            return RedirectToAction("Profile", "Home");
        }

        // Store the Entra user ID in session for the linking callback
        HttpContext.Session.SetString( Constants.SessionKeyLinkingEntraUserId, userId);
        HttpContext.Session.SetString(
            Constants.SessionKeyLinkingEntraDisplayName, 
            User.GetUserName() ?? "- missing username -");

        var properties = new AuthenticationProperties
        {
            RedirectUri = Url.Action(nameof(GoogleLinkCallback), "Account"),
            Items = { { "prompt", "select_account consent" } } // Force account selection
        };

        return Challenge(properties, GoogleDefaults.AuthenticationScheme);
    }

    public async Task<IActionResult> GoogleLinkCallback()
    {
        // User here is the google authenticated user. So we need to grab the data from here
        // and then replace the User with our custom claims.
        var googleUserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var entraUserId = HttpContext.Session.GetString(Constants.SessionKeyLinkingEntraUserId);
        var entraDisplayName = HttpContext.Session.GetString(Constants.SessionKeyLinkingEntraDisplayName);

        // Clear the session
        HttpContext.Session.Remove(Constants.SessionKeyLinkingEntraUserId);
        HttpContext.Session.Remove(Constants.SessionKeyLinkingEntraDisplayName);

        if (string.IsNullOrWhiteSpace(entraUserId) || string.IsNullOrWhiteSpace(googleUserId))
        {
            TempData["Error"] = "Linking session expired or Google authentication failed. Please try again.";
            return RedirectToAction("Index", "Home");
        }

        // Reset the User instance with Entra user claims in case something goes wrong.
        await RestoreEntraUserContext(entraUserId, entraDisplayName);

        // Link the Google account to the Entra user
        var success = await userService.LinkGoogleAccountAsync(entraUserId, googleUserId);

        if (success)
        {
            TempData["Success"] = "Google account linked successfully to your Entra ID profile!";
        }
        else
        {
            TempData["Error"] = "Failed to link Google account. It may already be linked or there was an error.";
        }

        // Redirect back to Profile - the user should now be authenticated with their original Entra session
        return RedirectToAction("Profile", "Home");
    }

    [Authorize]
    public async Task<IActionResult> UnlinkGoogle()
    {
        var userId = User.GetUserId();
        
        if (string.IsNullOrWhiteSpace(userId))
        {
            TempData["Error"] = "Invalid user authentication state for unlinking";
            return RedirectToAction("Profile", "Home");
        }

        var success = await userService.UnlinkGoogleAccountAsync(userId);
        if (success)
        {
            TempData["Success"] = "Google account unlinked successfully from your Entra ID profile!";
        }
        else
        {
            TempData["Error"] = "Failed to unlink Google account or no Google account was linked.";
        }

        return RedirectToAction("Profile", "Home");
    }

    private async Task RestoreEntraUserContext(string? userId, string? userName)
    {
        if (!string.IsNullOrWhiteSpace(userId) && !string.IsNullOrWhiteSpace(userName))
        {
            // Use the shared helper method from Program.cs
            var simplifiedClaims = AuthenticationHelper.CreateEntraUserClaims(userId, userName, Constants.CIAMSignInMethod);

            var newIdentity = new ClaimsIdentity(simplifiedClaims, CookieAuthenticationDefaults.AuthenticationScheme);
            var newPrincipal = new ClaimsPrincipal(newIdentity);

            // Sign in with the restored Entra user context
            var authProperties = new AuthenticationProperties
            {
                IsPersistent = false,
                ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1)
            };

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                newPrincipal, 
                authProperties);
        }
    }
}