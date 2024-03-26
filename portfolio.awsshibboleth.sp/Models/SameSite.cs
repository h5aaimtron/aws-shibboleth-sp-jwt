namespace portfolio.awsshibboleth.sp.Models
{
    public class SameSite
    {
        public static void CheckSameSite(HttpContext httpContext, CookieOptions options)
        {
            if (options.SameSite == SameSiteMode.None)
            {
                if (!BrowserSupportsSameSiteNone(httpContext.Request.Headers["User-Agent"].ToString()))
                {
                    // Unspecified - no SameSite will be included in the Set-Cookie.
                    options.SameSite = (SameSiteMode)(-1);
                }
            }
        }

        private static bool BrowserSupportsSameSiteNone(string userAgent)
        {
            // iOS 12 browsers don't support SameSite=None.
            if (userAgent.Contains("CPU iPhone OS 12") || userAgent.Contains("iPad; CPU OS 12"))
            {
                return false;
            }

            // macOS 10.14 Mojave browsers don't support SameSite=None.
            if (userAgent.Contains("Macintosh; Intel Mac OS X 10_14") && userAgent.Contains("Version/") && userAgent.Contains("Safari"))
            {
                return false;
            }

            // Old versions of Chrome don't support SameSite=None.
            if (userAgent.Contains("Chrome/5") || userAgent.Contains("Chrome/6"))
            {
                return false;
            }

            return true;
        }
    }
}
