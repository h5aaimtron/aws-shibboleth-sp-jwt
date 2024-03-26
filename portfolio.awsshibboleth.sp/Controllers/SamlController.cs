using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using portfolio.awsshibboleth.sp.Models;
using Sustainsys.Saml2.AspNetCore2;

namespace portfolio.awsshibboleth.sp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class SamlController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public SamlController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        /// <summary>
        /// Initializes the Signel Sign On process.
        /// </summary>
        /// <param name="returlUrl"></param>
        /// <returns></returns>
        [HttpGet("InitiateSingleSignOn"), AllowAnonymous]
        public IActionResult InitiateSingleSignOn(string returnUrl)
        {
            try
            {
                // Convert return url to uri object.
                Uri returnUri = new Uri(returnUrl);

                // Additional checks within the SP to verify the return url is allowed.
                // This item is coming from AWS Secrets Manager
                // Verify it matches the workstream running.
                if (!returnUri.Host.ToLower().EndsWith(Environment.GetEnvironmentVariable("AllowedOrigin"))) // && !returnUri.Host.StartsWith("localhost"))
                    return Unauthorized("Invalid Return Address");

                // Return Challenge to being sso.
                return new ChallengeResult(
                    Saml2Defaults.Scheme,
                    new AuthenticationProperties
                    {
                        RedirectUri = Url.Action(nameof(LoginCallback), new { returnUrl })
                    });
            }
            catch (Exception)
            {
                throw;
            }
        }

        /// <summary>
        /// Callback endpoint post sign-on.
        /// </summary>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
        [HttpGet("Callback"), AllowAnonymous]
        public async Task<IActionResult> LoginCallback(string returnUrl)
        {
            try
            {
                var authenticateResult = await HttpContext.AuthenticateAsync(ApplicationSamlConstants.External);

                if (!authenticateResult.Succeeded)
                    return Unauthorized();

                // Redirect them back to original url.
                if (!string.IsNullOrEmpty(returnUrl))
                    return Redirect(returnUrl);

                return Ok();
            }
            catch (Exception)
            {
                throw;
            }
        }

        /// <summary>
        /// Sign Out of application.
        /// </summary>
        /// <returns></returns>
        [HttpGet("SignOut"), AllowAnonymous]
        public async Task<IActionResult> SignOut()
        {
            try
            {
                return SignOut(
                    new AuthenticationProperties()
                    {
                        RedirectUri = ""
                    },
                    Saml2Defaults.Scheme);
            }
            catch (Exception)
            {
                throw;
            }
        }
    }
}
