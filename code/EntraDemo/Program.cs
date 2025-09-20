using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Graph;
using Microsoft.IdentityModel.Logging;
using System.Security.Claims;


Console.OutputEncoding = System.Text.Encoding.UTF8;

var builder = WebApplication.CreateBuilder(args);

// Enable PII logging for debugging (remove in production)
IdentityModelEventSource.ShowPII = true;

// Enable detailed logging
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.SetMinimumLevel(LogLevel.Debug);

// Create logger using the configured logging from builder
var logger = LoggerFactory.Create(config =>
{
    config.AddConsole();
    config.SetMinimumLevel(LogLevel.Debug);
}).CreateLogger<Program>();

const string banner = @"
 _____      _                        _ _   _       _____    _______  
|  ___|    | |                      (_) | | |     |_   _|  | | ___ \ 
| |__ _ __ | |_ _ __ __ _  __      ___| |_| |__     | |  __| | |_/ / 
|  __| '_ \| __| '__/ _` | \ \ /\ / / | __| '_ \    | | / _` |  __/  
| |__| | | | |_| | | (_| |  \ V  V /| | |_| | | |  _| || (_| | |     
\____/_| |_|\__|_|  \__,_|   \_/\_/ |_|\__|_| |_|  \___/\__,_\_|     
                                                                     
                                                                     
 _     _       _    _              ______ ________  ________         
| |   (_)     | |  (_)             |  _  \  ___|  \/  |  _  |        
| |    _ _ __ | | ___ _ __   __ _  | | | | |__ | .  . | | | |        
| |   | | '_ \| |/ / | '_ \ / _` | | | | |  __|| |\/| | | | |        
| |___| | | | |   <| | | | | (_| | | |/ /| |___| |  | \ \_/ /        
\_____/_|_| |_|_|\_\_|_| |_|\__, | |___/ \____/\_|  |_/\___/         
                             __/ |                                   
                            |___/                                    

";

logger.LogDebug(banner);


try
{
    // Add services
    builder.Services.AddControllersWithViews();
    
    // Add HttpClient for API calls
    builder.Services.AddHttpClient();

    // Add session support (requires memory cache)
    builder.Services.AddDistributedMemoryCache();
    builder.Services.AddSession(options =>
    {
        options.IdleTimeout = TimeSpan.FromMinutes(30);
        options.Cookie.HttpOnly = true;
        options.Cookie.IsEssential = true;
    });

    // Check Azure AD CIAM configuration
    var azureAdSection = builder.Configuration.GetSection("AzureAd");
    var authority = azureAdSection["Authority"];
    var clientId = azureAdSection["ClientId"];
    var clientSecret = azureAdSection["ClientSecret"];
    var tenantId = azureAdSection["TenantId"];
    
    logger.LogInformation("Azure AD CIAM Config - Authority: {Authority}, ClientId: {ClientId}, TenantId: {TenantId}, HasSecret: {HasSecret}", 
        authority, clientId, tenantId, !string.IsNullOrWhiteSpace(clientSecret));

    if (string.IsNullOrWhiteSpace(authority) || string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(clientSecret))
    {
        logger.LogError("❌ Azure AD CIAM configuration is incomplete!");
        throw new InvalidOperationException("Azure AD CIAM configuration is missing required values");
    }

    // Configure authentication with proper scheme handling for CIAM
    builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
    {
        options.LoginPath = "/Account/Login";
        options.LogoutPath = "/Account/Logout";
        options.ExpireTimeSpan = TimeSpan.FromHours(1);
        options.SlidingExpiration = true;
    })
    .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
    {
        options.Authority = authority;
        options.ClientId = clientId;
        options.ClientSecret = clientSecret;
        options.ResponseType = "code";
        options.CallbackPath = azureAdSection["CallbackPath"];
        options.SignedOutCallbackPath = azureAdSection["SignedOutCallbackPath"];
        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        
        // CIAM specific configuration
        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("email");
        
        options.TokenValidationParameters.NameClaimType = "name";
        options.TokenValidationParameters.RoleClaimType = "roles";
        options.TokenValidationParameters.ValidateIssuer = true;
        
        // Save tokens for downstream API calls
        options.SaveTokens = true;
        
        // Configure metadata address explicitly for CIAM
        options.MetadataAddress = $"{authority}/.well-known/openid-configuration";
        
        options.Events = new OpenIdConnectEvents
        {
            OnRedirectToIdentityProvider = context =>
            {
                logger.LogInformation("Redirecting to identity provider: {Issuer}", context.ProtocolMessage.IssuerAddress);
                return Task.CompletedTask;
            },
            OnAuthenticationFailed = context =>
            {
                logger.LogError("OIDC Authentication failed: {Error}", context.Exception?.Message);
                logger.LogError("Exception details: {Exception}", context.Exception?.ToString());
                context.Response.Redirect("/Home/Index?error=authentication_failed");
                context.HandleResponse();
                return Task.CompletedTask;
            },
            OnTokenValidated = async context =>
            {
                logger.LogInformation("OIDC Token validated for user: {User}", context.Principal?.Identity?.Name);
                
                // Create a simplified identity with only the claims we need
                var oidcIdentity = context.Principal?.Identity as ClaimsIdentity;
                if (oidcIdentity != null)
                {
                    // Get the essential claims from OIDC token
                    var userId = oidcIdentity.GetUPN() ?? oidcIdentity.GetPreferredUserName();
                    var userName = oidcIdentity.GetCustomName() ??
                        oidcIdentity.GetName() ?? 
                        oidcIdentity.GetPreferredUserName();

                    // Use the shared helper method (all users sign in via CIAM now)
                    AuthenticationHelper.SetupUserInContext(context, logger, userId, userName);
                }
            },
            OnRemoteFailure = context =>
            {
                logger.LogError("Remote authentication failure: {Error}", context.Failure?.Message);
                context.Response.Redirect("/Home/Index?error=remote_failure");
                context.HandleResponse();
                return Task.CompletedTask;
            }
        };
    });
    
    logger.LogInformation("✅ Azure AD CIAM authentication configured");

    // Add Google authentication
    var googleClientId = builder.Configuration["Authentication:Google:ClientId"];
    var googleClientSecret = builder.Configuration["Authentication:Google:ClientSecret"];
    
    logger.LogInformation("Google Config - ClientId: {ClientId}, HasSecret: {HasSecret}", 
        googleClientId, !string.IsNullOrWhiteSpace(googleClientSecret));

    if (!string.IsNullOrWhiteSpace(googleClientId) && !string.IsNullOrWhiteSpace(googleClientSecret))
    {
        builder.Services.AddAuthentication().AddGoogle(GoogleDefaults.AuthenticationScheme, googleOptions =>
        {
            googleOptions.ClientId = googleClientId;
            googleOptions.ClientSecret = googleClientSecret;
            googleOptions.CallbackPath = "/signin-google";
            googleOptions.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            
            // Request additional scopes for profile information
            googleOptions.Scope.Add("profile");
            googleOptions.Scope.Add("email");
            
            // Save tokens so we can access user information
            googleOptions.SaveTokens = true;
        });
        logger.LogInformation("✅ Google authentication added");
    }
    else
    {
        logger.LogWarning("⚠️ Google authentication skipped - missing configuration");
    }

    builder.Services.AddScoped(serviceProvider =>
    {
        string[] scopes = ["https://graph.microsoft.com/.default"];

        var options = new Azure.Identity.ClientSecretCredentialOptions
        {
            AuthorityHost = Azure.Identity.AzureAuthorityHosts.AzurePublicCloud,
        };

        // Use the tenant ID for Graph API access
        var clientSecretCredential = new Azure.Identity.ClientSecretCredential(
            tenantId,
            clientId,
            clientSecret,
            options);

        return new GraphServiceClient(clientSecretCredential, scopes);
    });

    // Add custom services
    builder.Services.AddScoped<IUserService, UserService>();
}
catch (Exception ex)
{
    logger.LogError(ex, "❌ Fatal error during service registration: {Message}", ex.Message);
    throw;
}

var app = builder.Build();



// Configure pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseSession();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();

