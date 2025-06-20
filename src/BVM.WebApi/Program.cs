using BVM.WebApi;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using System.Security;

var builder = WebApplication.CreateBuilder(args);

DIRegistrations.RegisterServices(builder);

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}

app.UseExceptionHandler(errorApp =>
{
    errorApp.Run(async context =>
    {
        var feature = context.Features.Get<IExceptionHandlerFeature>();

        if (feature?.Error is SecurityException securityException)
        {
            var problem = new ProblemDetails
            {
                Detail = securityException.Message,
                Title = "Security Exception",
                Status = StatusCodes.Status403Forbidden,
                Instance = context.Request.Path,
                Type = "https://httpstatuses.com/403",
            };
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsJsonAsync(problem);
        }
        else
        {
            // fallback to other exception handling thats not security
            // An unhandled exception is thrown and caught as this.
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            var detail = string.IsNullOrEmpty(feature?.Error.Message) ? "An error occurred while processing your request" : feature?.Error.Message;
            await context.Response.WriteAsJsonAsync(new ProblemDetails
            {
                Title = "Server Error",
                Status = StatusCodes.Status500InternalServerError,
                Detail = detail,
                Instance = context.Request.Path,
                Type = "https://httpstatuses.com/500"
            });
        }
    });
});

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint($"/swagger/{DIRegistrations.ApiVersion}/swagger.json", $"BVM API {DIRegistrations.ApiVersion}");
        c.RoutePrefix = ""; // Serve this route at /
    });
}
app.UseHttpsRedirection();

app.UseRouting();
app.UseHealthChecks("/health");

app.UseRateLimiter();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
