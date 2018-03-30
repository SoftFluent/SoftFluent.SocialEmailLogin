using System;
using System.Web.Security;
using System.Web;
using System.Diagnostics;

namespace SoftFluent.SocialEmailLogin.Demo
{
    public class AuthCallbackHandler : SocialEmailLogin.AuthCallbackHandler
    {
        protected override bool Authenticate(HttpContext context, AuthServiceProvider provider, AuthLoginOptions options, UserData userData)
        {
            string userName = userData.Email ?? userData.Name;
            if (string.IsNullOrEmpty(userName))
                return false;

            // create the user if he doesn't exist
            MembershipUser user = new MembershipUser("AspNetSqlMembershipProvider", userName, userName, userName, "AA", "AA", true, false, DateTime.Now, DateTime.Now, DateTime.Now, DateTime.Now, DateTime.Now);
            //MembershipUser user = Membership.GetUser(email);
            if (user == null)
            {
                string password = Membership.GeneratePassword(8, 0);
                user = Membership.CreateUser(userData.Email, password, userData.Email);
            }

            if ((options & AuthLoginOptions.Device) == AuthLoginOptions.Device)
            {
                HttpCookie authCookie = GetAuthCookie(userName, true, false);
                context.Response.Cookies.Add(authCookie);

                HttpCookie emailCookie = new HttpCookie(".EMAIL", userName)
                {
                    HttpOnly = false
                };
                context.Response.Cookies.Add(emailCookie);
            }
            else
            {
                // do Forms login
                HttpCookie authCookie = GetAuthCookie(userName, true, true);
                context.Response.Cookies.Add(authCookie);

                RedirectSuccess(context);
            }

            return true;
        }

        private static HttpCookie GetAuthCookie(string userName, bool createPersistentCookie, bool httpOnly)
        {
            FormsAuthenticationTicket ticket = new FormsAuthenticationTicket(2, userName, DateTime.Now, DateTime.Now.Add(FormsAuthentication.Timeout), createPersistentCookie, "SoftFluent.SocialEmailLogin", FormsAuthentication.FormsCookiePath);
            string encryptedTicket = FormsAuthentication.Encrypt(ticket);
            if (string.IsNullOrEmpty(encryptedTicket))
                throw new AuthException("OA0006: Failed to encrypt ticket.");

            HttpCookie cookie = new HttpCookie(FormsAuthentication.FormsCookieName, encryptedTicket)
            {
                HttpOnly = httpOnly,
                Path = FormsAuthentication.FormsCookiePath
            };

            if (FormsAuthentication.RequireSSL)
            {
                cookie.Secure = true;
            }

            if (FormsAuthentication.CookieDomain != null)
            {
                cookie.Domain = FormsAuthentication.CookieDomain;
            }

            if (ticket.IsPersistent)
            {
                cookie.Expires = ticket.Expiration;
            }
            return cookie;
        }

        protected override bool OnGetUserDataError(HttpContext context, Exception ex, int attempt)
        {
            Trace.WriteLine($"Attempt {attempt}: {ex}");
            return base.OnGetUserDataError(context, ex, attempt);
        }
    }
}
