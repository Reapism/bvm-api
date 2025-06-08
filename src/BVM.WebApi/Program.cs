using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using System.Security;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

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
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
