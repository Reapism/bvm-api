using Azure.Storage.Blobs;
using BVM.Core.Entities;
using BVM.Core.Exceptions;
using BVM.Core.Infrastructure.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Console;
using Microsoft.OpenApi.Models;

namespace BVM.WebApi
{
    public static class DIRegistrations
    {
        public const string ApiVersion = "v1";
        public static void RegisterServices(WebApplicationBuilder builder)
        {
            AddServices(builder);
        }

        private static void AddServices(WebApplicationBuilder builder)
        {
            var config = builder.Configuration
               .SetBasePath(builder.Environment.ContentRootPath)
               .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
               .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true, reloadOnChange: true)
               .AddUserSecrets<Program>();

            builder.Services.AddHealthChecks();
            builder.Services.AddAntiforgery(options =>
            {
                // Use a custom cookie name for clarity and to avoid collisions.
                options.Cookie.Name = "BlazarVisionApi.AntiForgeryCookie";

                // Prevent client-side scripts from accessing the antiforgery cookie.
                options.Cookie.HttpOnly = true;

                // Define a custom header name to be used in AJAX requests.
                options.HeaderName = "X-XSRF-TOKEN";

                if (builder.Environment.IsDevelopment())
                {
                    // In development, HTTPS might not be enforced, so allow non-secure cookies.
                    options.Cookie.SecurePolicy = CookieSecurePolicy.None;
                }
                else
                {
                    // In production, enforce HTTPS by only sending the antiforgery cookie over secure connections.
                    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                }
            });

            if (builder.Environment.IsProduction())
            {
                builder.Services.AddHsts(options =>
                {
                    // Preload indicates that the website is eligible to be added to browsers' HSTS preload lists.
                    options.Preload = true;
                    // IncludeSubDomains ensures the HSTS policy applies to all subdomains.
                    options.IncludeSubDomains = true;
                    // MaxAge defines how long (in seconds) the browser should remember to only use HTTPS.
                    options.MaxAge = TimeSpan.FromDays(60);  // Adjust this period based on your security requirements.
                });
            }

            builder.Services.AddLogging(logging =>
            {
                // Clear the default logging providers to avoid unintended logging behavior.
                logging.ClearProviders();

                if (builder.Environment.IsDevelopment())
                {
                    // Development settings:
                    // - Use Debug level logging to capture detailed information for troubleshooting.
                    // - The colored console output helps improve readability during active development.
                    logging.SetMinimumLevel(LogLevel.Debug);
                    logging.AddSimpleConsole(options =>
                    {
                        options.ColorBehavior = LoggerColorBehavior.Enabled;
                    });

                    logging.AddDebug();
                }
                else
                {
                    // Production settings:
                    // - Set a higher minimum level (Information) to reduce log verbosity.
                    //   This prevents performance degradation and avoids exposing sensitive details.
                    logging.SetMinimumLevel(LogLevel.Information);

                    // - Use the Console provider (or consider structured logging such as JSON)
                    //   to facilitate log parsing and integration with centralized log management systems.
                    logging.AddJsonConsole(options =>
                    {

                    });

                    // Optionally, add other secure and centralized logging providers.
                    // For example, on Windows you might integrate with the Windows Event Log:
                    // logging.AddEventLog();
                    //
                    // In cloud environments, consider using providers for Azure Application Insights,
                    // AWS CloudWatch, or other log aggregation services that help secure and manage logs.
                }
            });

            builder.Services.AddCors(options =>
            {
                if (builder.Environment.IsDevelopment())
                {
                    options.AddPolicy("DevCorsPolicy", policy =>
                    {
                        policy.AllowAnyOrigin()
                              .AllowAnyHeader()
                              .AllowAnyMethod();
                    });
                }

                if (builder.Environment.IsProduction())
                {
                    // In production, use only the origins specified in appsettings.json.
                    var apiPolicyName = "Cors:ApiPolicy";
                    var apiOrigins = builder.Configuration.GetSection(apiPolicyName).Get<string[]>();
                    if (apiOrigins is null || apiOrigins.Length == 0)
                    {
                        throw new InvalidApplicationConfigurationException(apiPolicyName, builder.Environment.EnvironmentName);
                    }

                    var clientPolicyName = "Cors:ClientPolicy";
                    var clientOrigins = builder.Configuration.GetSection(clientPolicyName).Get<string[]>();
                    if (clientOrigins is null || clientOrigins.Length == 0)
                    {
                        throw new InvalidApplicationConfigurationException(clientPolicyName, builder.Environment.EnvironmentName);
                    }

                    var allowedOrigins = apiOrigins.Union(clientOrigins).ToArray();

                    options.AddPolicy("ProdCorsPolicy", policy =>
                    {
                        policy.WithOrigins(allowedOrigins)
                              .AllowAnyHeader()
                              .AllowAnyMethod();
                    });
                }
            });

            builder.Services.AddDbContext<BvmDbContext>(o =>
            {
                if (builder.Environment.IsDevelopment())
                {
                    o.UseSqlite(builder.Configuration.GetConnectionString("ApiSqlLiteDb"), o =>
                    {
                        o.CommandTimeout(30);
                    });

                }
            });

            builder.Services.AddAuthorization(options =>
            {
                if (builder.Environment.IsProduction())
                {
                    options.FallbackPolicy = new AuthorizationPolicyBuilder()
                        .RequireAuthenticatedUser()
                        .Build();
                }
            });


            builder.Services.AddIdentity<AppUser, AppRole>(options =>
            {
                options.Password.RequireDigit = true;
                options.Password.RequiredLength = 8;
                options.Password.RequireNonAlphanumeric = false;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                options.Lockout.MaxFailedAccessAttempts = 5;
            })
            .AddEntityFrameworkStores<BvmDbContext>()
            .AddDefaultTokenProviders();

            // Configure the application cookie settings.
            builder.Services.ConfigureApplicationCookie(options =>
            {
                // Specify custom paths for login, logout, and access denied responses.
                options.LoginPath = "/login";        // Redirect to this path when authentication is required.
                options.LogoutPath = "/logout";        // Redirect here on logout.
                options.AccessDeniedPath = "/access-denied"; // Redirect here when the user lacks permission.

                // Set cookie expiration time and enable sliding expiration.
                options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
                options.SlidingExpiration = true;

                // Security settings for the cookie:
                // HttpOnly prevents client-side script access to the cookie.
                options.Cookie.HttpOnly = true;
                // Always require HTTPS in production to ensure the cookie is secure.
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                // SameSite Lax helps mitigate CSRF attacks while ensuring usability.
                options.Cookie.SameSite = SameSiteMode.Lax;
            });

            builder.Services.AddControllers()
                .AddJsonOptions(options =>
                {
                    options.JsonSerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase;
                });

            AddApiServices(builder);
            AddBlobServices(builder);
            AddSwagger(builder);
        }

        private static void AddSwagger(WebApplicationBuilder builder)
        {
            builder.Services.AddSwaggerGen(o =>
            {
                var estTimeZoneInfo = TimeZoneInfo.FindSystemTimeZoneById("Eastern Standard Time");
                var estDateTimeOffset = TimeZoneInfo.ConvertTime(DateTimeOffset.UtcNow, estTimeZoneInfo);

                var formattedAwokenDateTime = estDateTimeOffset.ToString("MM/dd/yyyy hh:mm:ss EST");

                o.SwaggerDoc(ApiVersion, new OpenApiInfo
                {
                    Version = ApiVersion,
                    Title = $"IDS API - {ApiVersion} {builder.Environment.EnvironmentName.ToUpper()}",
                    Description = $"The backend API for servicing the **IDS 2.0** application. See below for a quick glance at the API details, health, useful links.\n\n" +
                      $"| **Description**                               | **Details**                                   |\n" +
                      $"|-----------------------------------------------|-----------------------------------------------|\n" +
                      $"| **Last Awoken**                               | {formattedAwokenDateTime}                     |\n" +
                      $"| **Supported Content Types**                   | application/json                              |\n" +
                      $"| **Authentication Method**                     | JWT {JwtBearerDefaults.AuthenticationScheme}  |\n" +
                      $"| **Health Check**                              | [Check Health Status](/health)                |\n\n"
                });

                o.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    In = ParameterLocation.Header,
                    Description = "Please enter token",
                    Name = "Authorization",
                    Type = SecuritySchemeType.Http,
                    BearerFormat = "JWT",
                    Scheme = JwtBearerDefaults.AuthenticationScheme
                });

                o.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = JwtBearerDefaults.AuthenticationScheme
                            }
                        },
                        Array.Empty<string>()
                    }
                });
            });
        }

        private static void AddBlobServices(WebApplicationBuilder builder)
        {
            builder.Services.AddSingleton<BlobContainerClient>(sp =>
            {
                var configuration = sp.GetRequiredService<IConfiguration>();
                var connectionString = configuration["AzureBlobStorage:ConnectionString"];
                var containerName = configuration["AzureBlobStorage:ContainerName"];
                var blobServiceClient = new BlobServiceClient(connectionString);
                var containerClient = blobServiceClient.GetBlobContainerClient(containerName);
                return containerClient;
            });
        }

        private static void AddApiServices(WebApplicationBuilder builder)
        {
            var s = builder.Services;

        }
    }
}
