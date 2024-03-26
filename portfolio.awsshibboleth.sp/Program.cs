using portfolio.awsshibboleth.sp.Models;
using Sustainsys.Saml2.Metadata;
using Sustainsys.Saml2;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

// Configure Cookie Policy for SP
builder.Services.Configure<CookiePolicyOptions>(options =>
{
    // SameSiteMode.None is required to support SAML SSO
    options.MinimumSameSitePolicy = SameSiteMode.None;

    options.CheckConsentNeeded = context => false;

    options.Secure = CookieSecurePolicy.Always;

    // Older browsers do not support SameSiteMode.None.
    options.OnAppendCookie = cookieContext => SameSite.CheckSameSite(cookieContext.Context, cookieContext.CookieOptions);
    options.OnDeleteCookie = cookieContext => SameSite.CheckSameSite(cookieContext.Context, cookieContext.CookieOptions);
});

// Added Memory Cache (not really needed as we'll use sticky sessions in aws alb)
builder.Services.AddDistributedMemoryCache();

// Add Authentication
builder.Services.AddAuthentication(o =>
{
    o.DefaultScheme = ApplicationSamlConstants.Application;
    o.DefaultSignInScheme = ApplicationSamlConstants.External;
    o.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    o.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters()
    {
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ClockSkew = TimeSpan.FromMinutes(Convert.ToDouble(120)), // Set the expiration to 2 hours.
        ValidIssuer = Environment.GetEnvironmentVariable("Issuer"), // Configure valid token issuer.
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("JWTKey"))) // Pull Signing Key from Environment Var in AWS Secrets Manager.
    };
})
.AddCookie(ApplicationSamlConstants.Application)
.AddCookie(ApplicationSamlConstants.External)
.AddSaml2(options =>
{
    // Create Service Certificate
    var certificate = X509Certificate2.CreateFromPem(Environment.GetEnvironmentVariable("CertificatePem"), Environment.GetEnvironmentVariable("CertificateKey"));

    // Configure Options
    options.SPOptions.EntityId = new EntityId(Environment.GetEnvironmentVariable("SPEntityId"));
    options.SPOptions.ServiceCertificates.Add(certificate);
    options.SPOptions.ReturnUrl = new Uri(Environment.GetEnvironmentVariable("SPDefaultRedirectUrl"));
    options.SPOptions.PublicOrigin = new Uri(Environment.GetEnvironmentVariable("IDPPublicOrigin"));
    options.IdentityProviders.Add(
        new IdentityProvider(
            new EntityId(Environment.GetEnvironmentVariable("IDPEntityId")), options.SPOptions)
        {
            LoadMetadata = true,
            MetadataLocation = Environment.GetEnvironmentVariable("IDPMetadataLocation"),
            AllowUnsolicitedAuthnResponse = true
        });
});

// Add Session configuration for cookies.
builder.Services.AddSession(options =>
{
    options.Cookie.IsEssential = true;
    options.Cookie.SameSite = SameSiteMode.None;
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

// Add Cors Policy
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", builder =>
    {
        builder.AllowCredentials()
        .SetIsOriginAllowedToAllowWildcardSubdomains()
        .WithOrigins("http://localhost:4200", "https://*.com") // Configured localhost:4200 for the Single Page App (Angular) we would use for this example.
        .AllowAnyMethod()
        .AllowAnyHeader();
    });
});

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Configure for your use and rename as you see fit. 
app.UseCors("AllowAll");

app.UseSession();

app.UseAuthentication();

app.UseAuthorization();

// Removing this as the AWS ALB will handle ssl and communicate with the docker container on port 8080 (.NET 8 default port)
//app.UseHttpsRedirection();

app.MapControllers();

app.Run();
