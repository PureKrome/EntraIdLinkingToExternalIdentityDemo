using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace EntraDemo.Controllers;

public class HomeController(
    IUserService userService, 
    IHttpClientFactory httpClientFactory, 
    IConfiguration configuration) : Controller
{
    private readonly HttpClient _httpClient = httpClientFactory.CreateClient();
    private readonly IConfiguration _configuration = configuration;

    public IActionResult Index(string? error = null)
    {
        if (!string.IsNullOrWhiteSpace(error))
        {
            ViewBag.AuthError = error switch
            {
                "authentication_failed" => "Authentication failed. Please try again.",
                "remote_failure" => "Remote authentication service is unavailable. Please try again later.",
                _ => "An authentication error occurred."
            };
        }
        
        return View();
    }

    [Authorize]
    public async Task<IActionResult> Profile()
    {
        // Get the simplified claims from HttpContext.User
        var userId = User.GetUserId();
        var userName = User.GetUserName();
        
        if (string.IsNullOrWhiteSpace(userId))
        {
            TempData["Error"] = "User authentication error. Could not determine user ID.";
            return RedirectToAction("Index");
        }

        // Now fetch full Entra user details using the user ID
        var entraUser = await userService.GetUserByIdAsync(userId);
        if (entraUser == null)
        {
            TempData["Error"] = "Unable to retrieve user profile from Entra ID.";
            return RedirectToAction("Index");
        }

        // Set the user data for the view
        ViewBag.EntraUser = entraUser;
        ViewBag.UserIdentities = entraUser.Identities?.ToList() ?? [];
        ViewBag.UserId = userId;
        ViewBag.UserName = userName;

        // Check if Google account is linked (using the user ID)
        var isGoogleLinked = await userService.IsGoogleAccountLinkedAsync(userId);
        var linkedGoogleId = await userService.GetLinkedGoogleAccountAsync(userId);
        ViewBag.GoogleLinked = isGoogleLinked;
        ViewBag.LinkedGoogleId = linkedGoogleId;

        // Debug information
        ViewBag.AllClaims = User.Claims.Select(c => new { c.Type, c.Value }).ToList();

        return View();
    }

    // Add a test endpoint to check OIDC configuration
    public async Task<IActionResult> TestCiamConfig()
    {
        try
        {
            var ciamAuthority = _configuration["AzureAd:Authority"];
            var configUrl = $"{ciamAuthority}/.well-known/openid-configuration";
            
            var response = await _httpClient.GetAsync(configUrl);
            var content = await response.Content.ReadAsStringAsync();
            
            ViewBag.ConfigUrl = configUrl;
            ViewBag.StatusCode = response.StatusCode;
            ViewBag.IsSuccess = response.IsSuccessStatusCode;
            ViewBag.Content = content;
            
            return View();
        }
        catch (Exception exception)
        {
            ViewBag.Error = exception.Message;
            return View();
        }
    }
}