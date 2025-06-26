using Azure.Storage.Blobs;
using BVM.Core.Abstractions.Data;
using BVM.Core.Entities;
using BVM.Core.Exceptions;
using BVM.WebApi.Configurations;
using BVM.WebApi.Infrastructure.Data;
using BVM.WebApi.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Console;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;
using System.Threading.RateLimiting;

namespace BVM.WebApi
{
    public static class DIRegistrations
    {
        public const string ApiVersion = "v1";
        public static void RegisterServices(WebApplicationBuilder builder)
        {
            AddDotNetServices(builder);
            AddBlobServices(builder);
            AddSwagger(builder);
            AddApiServices(builder);
        }

        private static void AddDotNetServices(WebApplicationBuilder builder)
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

                options.AddPolicy("CorsPolicy", policy =>
                {
                    policy.WithOrigins(allowedOrigins)
                          .AllowCredentials()
                          .AllowAnyHeader()
                          .AllowAnyMethod();
                });

            });

            builder.Services.AddDbContext<BvmDbContext>(o =>
            {
                if (builder.Environment.IsDevelopment())
                {
                    o.EnableDetailedErrors();
                    o.EnableSensitiveDataLogging();
                }
                o.UseSqlServer(builder.Configuration.GetConnectionString("ApiDb"), o =>
                {
                    o.CommandTimeout(30);
                });
            });
            builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("Jwt"));

            builder.Services.AddSingleton(
                sp => sp.GetRequiredService<IOptions<JwtSettings>>().Value);
            builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                var jwtSection = builder.Configuration.GetSection("Jwt");

                var jwt = jwtSection.Get<JwtSettings>();
                var jwtKeyBytes = Encoding.UTF8.GetBytes(jwt.Secret);

                options.RequireHttpsMetadata = true;
                options.SaveToken = true;

                builder.Configuration.Bind("Jwt", options);

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(jwtKeyBytes),

                    ValidateIssuer = true,
                    ValidIssuer = jwt.Issuer,

                    ValidateAudience = true,
                    ValidAudience = jwt.Audience,

                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                };
            });

            builder.Services.AddAuthorization();

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

            builder.Services.AddControllers()
                .AddJsonOptions(options =>
                {
                    options.JsonSerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase;
                });

            builder.Services.AddRateLimiter(options =>
            {
                options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
                    RateLimitPartition.GetFixedWindowLimiter(
                        partitionKey: httpContext.User.Identity?.Name ?? httpContext.Request.Headers.Host.ToString(),
                        factory: partition => new FixedWindowRateLimiterOptions
                        {
                            AutoReplenishment = true,
                            PermitLimit = 10,
                            QueueLimit = 0,
                            Window = TimeSpan.FromMinutes(1)
                        }));
            });
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
                    Title = $"BVM API - {ApiVersion} {builder.Environment.EnvironmentName.ToUpper()}",
                    Description = $"The backend API for servicing the **BVM** application. See below for a quick glance at the API details, health, useful links.\n\n" +
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

            s.AddSingleton<IDateTimeProvider, EasternDateTimeProvider>();
            s.AddScoped<IAuthService, AuthService>();
            s.AddScoped(typeof(IRepository<>), typeof(Repository<>));
            s.AddScoped<IUnitOfWork, UnitOfWork>();
            //s.AddScoped(typeof(IRepository<>), typeof(<>));
        }
    }
}
