using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace EntraDemo.Controllers;

[Authorize]
public class UserController(IUserService userService) : Controller
{
    public IActionResult Create()
    {
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Create(CreateUserViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var success = await userService.CreateUserInEntraIdAsync(model);
        
        if (success)
        {
            TempData["Success"] = "User created successfully in EntraID";
            return RedirectToAction("List");
        }
        else
        {
            ModelState.AddModelError("", "Failed to create user in EntraID");
            return View(model);
        }
    }

    public async Task<IActionResult> List()
    {
        var users = await userService.GetAllUsersAsync();
        var viewModel = new UserListViewModel { Users = users };
        return View(viewModel);
    }
}