using System;
using System.Web;
using System.Web.Security;
using CodeFluent.Runtime.Utilities;
using SoftFluent.SocialEmailLogin.Configuration;
using SoftFluent.SocialEmailLogin.Web.Security;

namespace SoftFluent.SocialEmailLogin.Web.Callback
{
    public class AuthCallbackHandler : IHttpHandler
    {
        public bool IsReusable
        {
            get
            {
                return true;
            }
        }

        public void ProcessRequest(HttpContext context)
        {
            if (context == null)
                throw new ArgumentNullException("context");

            // get the provider
            string providerName = ConvertUtilities.Nullify(context.Request[AuthServiceProvider.ProviderParameter], true);
            if (providerName == null)
                return;

            AuthLoginOptions options = ConvertUtilities.ChangeType(context.Request[AuthServiceProvider.OptionsParameter], AuthLoginOptions.None);

            AuthServiceProvider provider = SocialEmailLoginSection.Current.Authentication.GetServiceProvider(providerName);
            if (provider == null)
                return;

            // get the provider-verified email
            string email = provider.GetEmail(context);
            if (string.IsNullOrEmpty(email))
                return;

            // create the user if he doesn't exist
            // username is same as email
            MembershipUser user = new MembershipUser("AspNetSqlMembershipProvider", email, email, email, "AA", "AA", true, false, DateTime.Now, DateTime.Now, DateTime.Now, DateTime.Now, DateTime.Now);
            //MembershipUser user = Membership.GetUser(email);
            if (user == null)
            {
                string password = Membership.GeneratePassword(8, 0);
                user = Membership.CreateUser(email, password, email);
            }

            if ((options & AuthLoginOptions.Device) == AuthLoginOptions.Device)
            {
                HttpCookie authCookie = GetAuthCookie(email, true, false);
                context.Response.Cookies.Add(authCookie);

                HttpCookie emailCookie = new HttpCookie(".EMAIL", email);
                emailCookie.HttpOnly = false;
                context.Response.Cookies.Add(emailCookie);
            }
            else
            {
                // do Forms login
                HttpCookie authCookie = GetAuthCookie(email, true, true);
                context.Response.Cookies.Add(authCookie);

                // redirect
                string url = ConvertUtilities.Nullify(context.Request[AuthServiceProvider.UrlParameter], true);
                if (string.IsNullOrEmpty(url))
                {
                    url = AuthServiceProvider.GetAbsoluteApplicationPath();
                }
                context.Response.Redirect(url, false);
            }
        }

        private static HttpCookie GetAuthCookie(string userName, bool createPersistentCookie, bool httpOnly)
        {
            FormsAuthenticationTicket ticket = new FormsAuthenticationTicket(2, userName, DateTime.Now, DateTime.Now.Add(FormsAuthentication.Timeout), createPersistentCookie, "SoftFluent.SocialEmailLogin", FormsAuthentication.FormsCookiePath);
            string encryptedTicket = FormsAuthentication.Encrypt(ticket);
            if (string.IsNullOrEmpty(encryptedTicket))
                throw new AuthException("OA0006: Failed to encrypt ticket.");

            HttpCookie cookie = new HttpCookie(FormsAuthentication.FormsCookieName, encryptedTicket);
            cookie.HttpOnly = httpOnly;
            cookie.Path = FormsAuthentication.FormsCookiePath;

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
    }
}
