using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace BVM.WebApi.Controllers;

[ApiController]
[AllowAnonymous]
[Route("api/[controller]")]
public abstract class ApiControllerBase
{

}
