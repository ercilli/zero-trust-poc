using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = builder.Configuration["Jwt:Authority"] ?? "http://keycloak:8080/realms/zero-trust-realm";
        options.Audience = "payments-api";
        options.RequireHttpsMetadata = false;
        // Sin esto, ASP.NET Core remapea el claim "roles" al URI legado
        // http://schemas.microsoft.com/ws/2008/06/identity/claims/role,
        // rompiendo tanto el chequeo por Type=="roles" como RoleClaimType.
        options.MapInboundClaims = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ClockSkew = TimeSpan.Zero,
            RoleClaimType = "roles"
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RequirePaymentsWrite", policy =>
        policy.RequireAssertion(ctx =>
            ctx.User.HasClaim(c => c.Type == "roles" && c.Value.Split(',').Contains("Payments.Write")) ||
            ctx.User.IsInRole("Payments.Write")));
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health", () => Results.Ok(new { status = "Healthy", timestamp = DateTime.UtcNow }));

app.MapPost("/api/v1/pagos", (HttpContext context) =>
{
    var clientCertDn = context.Request.Headers["X-Client-Cert-DN"].FirstOrDefault() ?? "Unknown";
    return Results.Ok(new
    {
        message = "Pago procesado con éxito.",
        authorizedClient = clientCertDn,
        processedAt = DateTime.UtcNow
    });
}).RequireAuthorization("RequirePaymentsWrite");

app.Run();