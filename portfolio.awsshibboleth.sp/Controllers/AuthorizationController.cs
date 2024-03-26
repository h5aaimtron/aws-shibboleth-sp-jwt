using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using portfolio.awsshibboleth.sp.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace portfolio.awsshibboleth.sp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthorizationController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly string _tokenIssuer;
        private readonly string _tokenKey;

        public AuthorizationController(IConfiguration configuration)
        {
            _configuration = configuration;

            // Use appsettings if environment variables not set.
            if (Environment.GetEnvironmentVariable("") == null)
            {
                _tokenIssuer = _configuration["JWT:Issuer"];
                _tokenKey = _configuration["JWT:Key"];
            }
            else
            {
                _tokenIssuer = Environment.GetEnvironmentVariable("Issuer");
                _tokenKey = Environment.GetEnvironmentVariable("JWTKey");
            }
        }

        /// <summary>
        /// Get the token if they are a valid user.
        /// </summary>
        /// <returns></returns>
        [HttpGet, AllowAnonymous]
        public async Task<IActionResult> Get()
        {
            try
            {
                var authenticateResult = await HttpContext.AuthenticateAsync(ApplicationSamlConstants.External);

                if (!authenticateResult.Succeeded)
                    return Unauthorized();

                // Create the JWT Token
                var token = this.CreateJwtSecurityToken(authenticateResult);
                var jwtSecurity = new JwtSecurityTokenHandler().WriteToken(token);

                // Check if security token was created.
                if (jwtSecurity == null)
                    return Unauthorized();

                return Ok(jwtSecurity);
            }
            catch (Exception)
            {
                throw;
            }
        }

        /// <summary>
        /// Create the JWT Token based on the assertion.
        /// </summary>
        /// <param name="authenticateResult"></param>
        /// <returns></returns>
        private JwtSecurityToken CreateJwtSecurityToken(AuthenticateResult authenticateResult)
        {
            try
            {
                if (authenticateResult.Principal == null)
                    throw new Exception("Principal not found.");

                var nameIdentifierClaim = authenticateResult.Principal.FindFirst(ClaimTypes.NameIdentifier);
                if (nameIdentifierClaim == null)
                    throw new Exception("Name Identifier not found.");

                var claimsIdentity = new ClaimsIdentity(ApplicationSamlConstants.Application);
                claimsIdentity.AddClaim(nameIdentifierClaim);

                var username = nameIdentifierClaim.Value.ToString();

                var claims = new List<Claim>
                {
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.Sub, username)
                };

                var samlClaims = authenticateResult.Principal.Claims;
                foreach (var samlClaim in samlClaims)
                {
                    // TODO: Map your rquired claims to JWT claims.
                    // You might use a switch(samlClaim.Type.ToString()) to
                    // build extract and map.
                    // claims.Add(new Claim(samlClaim.Type.ToString(), samlClaim.Value.ToString()));
                }

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_tokenKey));
                var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                return new JwtSecurityToken(
                    _tokenIssuer,
                    "", // You can set your audience here.
                    claims,
                    expires: DateTime.Now.AddHours(1), // Set 1 hour expiration
                    signingCredentials: credentials);
            }
            catch (Exception)
            {
                throw;
            }
        }
    }
}
